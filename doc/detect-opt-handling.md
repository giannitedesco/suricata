# Suricata Rule Option Handling Internals

This document describes how rule keywords (detect options) are parsed, classified,
and routed into the internal `Signature` data structures during rule loading.

---

## 1. Keyword Classification

Every keyword is registered in `sigmatch_table[]` (a global `SigTableElmt` array).
The `flags` field classifies keywords:

| Flag | Bit | Meaning |
|------|-----|---------|
| `SIGMATCH_NOOPT` | 0 | Keyword takes no argument |
| `SIGMATCH_OPTIONAL_OPT` | 4 | Argument is optional |
| `SIGMATCH_HANDLE_NEGATION` | 7 | Parser handles `!` negation |
| `SIGMATCH_INFO_CONTENT_MODIFIER` | 8 | Old-style content modifier (e.g. `http_uri`) |
| `SIGMATCH_INFO_STICKY_BUFFER` | 9 | Sticky buffer keyword (e.g. `http.uri`, `tls.sni`) |
| `SIGMATCH_INFO_DEPRECATED` | 10 | Deprecated keyword |

**Transforms** (`dotprefix`, `strip_whitespace`, etc.) are registered separately via
`SCDetectHelperTransformRegister()` using a `SCTransformTableElmt` struct, not
`SigTableElmt`. They are identified by a non-NULL `Transform` function pointer.

### Querying keyword categories with `keywords.json`

Suricata emits a machine-readable keyword table at startup via `--list-keywords=json`
(also written to `keywords.json` when built with the appropriate flag). Each entry
records which callbacks the keyword registered. This can be used to classify keywords
without reading C source.

The key insight is that three callback fields act as proxies for the runtime dispatch
tier a keyword uses:

- **`match`** — keyword implements `SigTableElmt.Match` (or `AppLayerTxMatch` /
  `FileMatch`): it does its own runtime evaluation directly against packet/flow/tx data.
- **`free`** — keyword's `Setup()` allocated a `SigMatchCtx *ctx` that must be freed:
  the keyword has parsed state, meaning it does real work beyond just mutating a prior
  keyword.
- **`app-layer-tx-match`** — keyword implements `SigTableElmt.AppLayerTxMatch`:
  it matches against app-layer transaction fields (not buffer bytes).

Combining these three fields partitions keywords into three tiers:

**Tier 1 — pure parse-time** (no `match`, no `free`, not `sticky-buffer`):
keywords that only mutate parser state or a prior keyword's ctx during `Setup()` and
have no runtime presence at all. Includes relative modifiers (`depth`, `within`,
`distance`, `offset`), meta keywords (`sid`, `msg`, `rev`), transforms (`dotprefix`,
`to_lowercase`), and old-style content modifiers (`http_uri`).

```sh
jq -r 'select(
  (.callbacks | index("match") | not) and
  (.callbacks | index("free") | not) and
  (.flags | index("sticky-buffer") | not)
) | .name' keywords.json
```

**Tier 2 — `AppLayerTxMatch` field-checkers** (no `match`, has `free`, has
`app-layer-tx-match`): keywords that allocate ctx in `Setup()` and match at runtime
against app-layer transaction *fields* (integers, enums, flags) rather than buffer
bytes. Examples: `ssl_version`, `tls_cert_valid`, `dns.rcode`, `mqtt.type`,
`nfs_procedure`.

```sh
jq -r 'select(
  (.callbacks | index("match") | not) and
  (.callbacks | index("free") != null) and
  (.callbacks | index("app-layer-tx-match") != null)
) | .name' keywords.json
```

**Tier 3 — inspection-engine-driven** (no `match`, has `free`, no
`app-layer-tx-match`): keywords evaluated by `DetectEngineContentInspectionBuffer()`
or an equivalent inline dispatcher — they have no `Match` callback because the
inspection engine calls into them directly via the `SigMatchData` type switch. This
is the category that includes `content`, `pcre`, `isdataat`, `byte_test`,
`byte_jump`, `byte_extract`, `byte_math`, `bsize`, `dataset`, `entropy`, `xor`,
`gunzip`, `zlib_deflate`, `asn1`, `base64_decode`, and hash matchers.

```sh
jq -r 'select(
  (.callbacks | index("match") | not) and
  (.callbacks | index("free") != null) and
  (.callbacks | index("app-layer-tx-match") | not)
) | .name' keywords.json
```

Note that Tier 3 is still an approximation: it is not possible to determine purely
from `keywords.json` whether a keyword's `Setup()` routes it into a buffer list vs.
`DETECT_SM_LIST_MATCH`. That distinction is encoded in the `Setup()` implementation
itself (see §3–4).

---

## 2. Where SigMatches Live: `smlists[]` vs `buffers[]`

`SignatureInitData` (alive only during rule parsing, freed after `SigGroupBuild`)
holds two parallel structures for `SigMatch` lists:

```c
// Fixed array of "built-in" lists (indices 0..DETECT_SM_LIST_MAX-1)
struct SigMatch_ *smlists[DETECT_SM_LIST_MAX];

// Dynamic array of buffer slots (list IDs >= DETECT_SM_LIST_MAX)
SignatureInitDataBuffer *buffers;   // heap-allocated, grows on demand
uint32_t buffer_index;
```

The split is a single numeric threshold in `SCSigMatchAppendSMToList()`:

```c
if (list < DETECT_SM_LIST_MAX) {
    // → smlists[list]   (built-in: packet match, payload, postmatch, etc.)
} else {
    // → buffers[]       (dynamic: http.uri, tls.sni, dns.query, file.data, …)
}
```

### Built-in list IDs (`< DETECT_SM_LIST_MAX`)

| ID | Name | Usage |
|----|------|-------|
| 0 | `DETECT_SM_LIST_MATCH` | Packet-level keywords (ttl, flags, dsize…) |
| 1 | `DETECT_SM_LIST_PMATCH` | Payload / stream content (the default) |
| 2 | `DETECT_SM_LIST_BASE64_DATA` | After `base64_data;` |
| 3 | `DETECT_SM_LIST_POSTMATCH` | Post-match actions (flowbits set, etc.) |
| 4 | `DETECT_SM_LIST_TMATCH` | Tagging |
| 5 | `DETECT_SM_LIST_SUPPRESS` | Threshold suppression |
| 6 | `DETECT_SM_LIST_THRESHOLD` | Threshold |

Dynamic buffer IDs start at `DETECT_SM_LIST_DYNAMIC_START = DETECT_SM_LIST_MAX`.
They are allocated at engine startup by `DetectBufferTypeGetByName()` when
keywords register their buffer (e.g. `g_http_uri_buffer_id = DetectBufferTypeGetByName("http_uri")`).

---

## 3. `init_data->list`: the Active Buffer Pointer

`init_data->list` is an integer that tracks *which list the next keyword should
append to*. It is the central piece of state during rule parsing.

```c
#define DETECT_SM_LIST_NOTSET  INT_MAX   // nothing selected
```

### Lifecycle

**Initialised** to `DETECT_SM_LIST_NOTSET` in `SigAlloc()`.

**Set** by:

| Operation | Who | Result |
|-----------|-----|--------|
| Sticky buffer keyword (e.g. `tls.sni`) | `SCDetectBufferSetActiveList(de_ctx, s, id)` | `list = id`, `list_set = true` |
| `base64_data` keyword | directly: `s->init_data->list = DETECT_SM_LIST_BASE64_DATA` | — |
| Transform consumed (first content after transform) | `DetectBufferGetActiveList()` replaces with derived ID | `list = derived_id`, `list_set = false` |

**Reset** by:

| Operation | Who |
|-----------|-----|
| `pkt_data` keyword | `s->init_data->list = DETECT_SM_LIST_NOTSET` |
| `SCSigMatchAppendSMToList()` — if appending list ≠ current list | auto-reset to `NOTSET` |

**Read** by: `content`, `pcre`, `isdataat`, `bsize`, `datarep`, `lua`, and any other
keyword that calls `SCSigMatchAppendSMToList(..., s->init_data->list)` or checks
`s->init_data->list` for routing.

### The `list_set` flag

`list_set` is a boolean companion to `list`. It is `true` only immediately after a
sticky buffer keyword sets the list, and is cleared to `false` once the first
content keyword consumes any pending transforms (via `DetectBufferGetActiveList()`).
It has two purposes:

1. **Guards transforms**: `SCDetectSignatureAddTransform()` rejects a transform
   unless `list_set == true`, enforcing *"transforms must directly follow sticky
   buffer keywords"*.
2. **Disambiguates**: distinguishes a freshly-set sticky buffer from an
   already-consumed derived buffer.

---

## 4. Keyword Categories and What Their Setup() Does

### 4a. Sticky Buffer Keywords (`SIGMATCH_INFO_STICKY_BUFFER`)

Examples: `http.uri`, `tls.sni`, `dns.query`, `file.data`

Their `Setup()` calls `SCDetectBufferSetActiveList(de_ctx, s, buffer_id)`, which:
- Rejects if `transforms.cnt > 0` but no matches yet consumed them
- Sets `s->init_data->list = buffer_id`
- Sets `s->init_data->list_set = true`

After this, subsequent `content`/`pcre`/`isdataat` keywords will route into
`buffers[]` with that ID.

### 4b. Transforms

Examples: `dotprefix`, `strip_whitespace`, `to_lowercase`, `urldecode`

Their `Setup()` calls `SCDetectSignatureAddTransform(s, transform_id, options)`,
which:
- Rejects unless `list_set == true` (must directly follow a sticky buffer)
- Appends to `s->init_data->transforms[]`, increments `transforms.cnt`

Transforms are *pending* — not yet committed to a buffer. They are consumed by
the next `DetectBufferGetActiveList()` call (triggered by the first `content` after
the transforms).

### 4c. Content-Consuming Keywords (`content`, `pcre`, `isdataat`, …)

These all follow the same pattern in `Setup()`:

```c
// 1. Resolve any pending transforms into a derived buffer ID
if (DetectBufferGetActiveList(de_ctx, s) == -1)
    goto error;

// 2. Determine target list
int sm_list = s->init_data->list;
if (sm_list == DETECT_SM_LIST_NOTSET)
    sm_list = DETECT_SM_LIST_PMATCH;   // default: raw payload

// 3. Append
SCSigMatchAppendSMToList(de_ctx, s, TYPE, ctx, sm_list);
```

`DetectBufferGetActiveList()` is the transform-consumption step:

```c
if (s->init_data->list && s->init_data->transforms.cnt) {
    // Create or reuse a derived buffer type for (base_buffer + transforms)
    int new_list = DetectEngineBufferTypeGetByIdTransforms(
            de_ctx, s->init_data->list,
            s->init_data->transforms.transforms,
            s->init_data->transforms.cnt);
    s->init_data->list = new_list;
    s->init_data->list_set = false;
    s->init_data->transforms.cnt = 0;   // ← transforms consumed
}
```

This means **transforms are sticky**: once consumed into `new_list`, every
subsequent `content`/`pcre` in the same buffer context goes to the same derived
list — until a new sticky buffer keyword resets `init_data->list`.

**Example**: `tls.sni; dotprefix; content:"foo"; content:"bar";`

```
SigAlloc:              list = NOTSET
tls.sni:               list = g_tls_sni_id,     list_set = true
dotprefix:             transforms.cnt = 1
content:"foo":
  DetectBufferGetActiveList:
    new_list = derived(tls_sni + dotprefix)
    list = new_list,  list_set = false,  transforms.cnt = 0
  → appended to buffers[new_list]
content:"bar":
  DetectBufferGetActiveList: transforms.cnt == 0, no-op
  sm_list = list = new_list   ← same derived buffer
  → appended to buffers[new_list]
```

To get back to the *untransformed* buffer after consuming transforms:
```
tls.sni; dotprefix; content:"foo"; tls.sni; content:"bar";
```
`"foo"` → dotprefix-derived buffer; `"bar"` → plain `tls.sni` buffer.
This works because `transforms.cnt == 0` when the second `tls.sni` fires.
Calling `tls.sni` *before* a content has consumed pending transforms is an error.

### 4d. Old-Style Content Modifiers (`SIGMATCH_INFO_CONTENT_MODIFIER`)

Examples: `http_uri`, `http_server_body`, `rawbytes`

These predate sticky buffers. Their `Setup()` (via `DetectEngineContentModifierBufferSetup`):
- **Hard-rejects** if `list != NOTSET` — completely incompatible with any active sticky
  buffer. The only way to use them in the same rule as a sticky buffer is to reset with
  `pkt_data;` first (which sets `list = NOTSET`).
- Finds the **last `DETECT_CONTENT` in `smlists[DETECT_SM_LIST_PMATCH]`** via
  `DetectGetLastSMByListId()`
- **Moves** that SigMatch from `smlists[PMATCH]` to the appropriate buffer
- Does **not** change `init_data->list` — it stays `NOTSET` throughout

They are the dual of sticky buffers: sticky buffers set context for future keywords;
content modifiers reach back and change where a past keyword lives.

Each old-style keyword has a `sigmatch_table[X].alternative` pointing to its modern
sticky-buffer equivalent (e.g. `http_uri` → `http.uri`).

`uricontent` is a compound old-style modifier: its `Setup()` calls `DetectContentSetup`
(which appends the content to `PMATCH` using the current `list`, requiring `NOTSET`) then
`DetectHttpUriSetup` (which moves it to `g_http_uri_buffer_id`). It has the same
sticky-buffer incompatibility as all other old-style modifiers.

### 4e. Relative Modifiers: `within`, `distance`, `offset`, `depth`

These do **not** change which buffer a keyword goes into. They:
- Call `DetectGetLastSMFromLists(s, DETECT_CONTENT, -1)` to find the most-recently
  parsed `content` SigMatch
- Modify flags/fields on that `DetectContentData` in-place (e.g. `cd->flags |= DETECT_CONTENT_WITHIN`)
- Never call `DetectBufferGetActiveList()` or `SCSigMatchAppendSMToList()`
- Do not consume or advance `init_data->list`

---

## 5. Runtime Dispatch: What Callbacks Receive

`SigTableElmt` has four distinct runtime callback slots. A keyword uses at most one;
`content`/`pcre`/`isdataat` use **none of them** — they are handled by a separate
inspection engine.

### `Match(det_ctx, Packet *, sig, SigMatchCtx *)`

Used by **packet-field keywords** in `DETECT_SM_LIST_MATCH`: `ttl`, `flags`, `itype`,
`tos`, `dsize`, `flow`, `flowbits`, etc.

The callback receives the raw `Packet *` and the keyword's parsed config in
`SigMatchCtx *ctx` (an opaque wrapper — each keyword casts it to its own struct,
e.g. `DetectTtlData *`). It reads packet struct fields directly.

### `AppLayerTxMatch(det_ctx, Flow *, flags, alstate, txv, sig, SigMatchCtx *)`

A small set of keywords live in `DETECT_SM_LIST_MATCH` but need app-layer context
(e.g. `app-layer-protocol`, `app-layer-event`). They receive the flow, raw
app-layer state pointer, and transaction pointer — but **no buffer**.

### `FileMatch(det_ctx, Flow *, flags, File *, sig, SigMatchCtx *)`

File-inspecting keywords (`filemagic`, `filesize`, `filename`, etc.) receive a
`File *` struct.

### Content inspection — no `Match` callback

`content`, `pcre`, and `isdataat` register **no** `Match`, `AppLayerTxMatch`, or
`FileMatch` callback. They are evaluated entirely inside
`DetectEngineContentInspectionBuffer()`:

```c
bool DetectEngineContentInspectionBuffer(de_ctx, det_ctx, s, smd,
        Packet *p, Flow *f, const InspectionBuffer *b, inspection_mode)
```

The `InspectionBuffer *b` carries:

| Field | Meaning |
|---|---|
| `b->inspect` | pointer to the raw bytes |
| `b->inspect_len` | byte count |
| `b->inspect_offset` | offset into the original data (for relative modifiers) |
| `b->flags` | e.g. `DETECT_CI_FLAGS_END_MATCH` |

For `DETECT_SM_LIST_PMATCH` the bytes are raw packet payload or reassembled stream
data. For a dynamic app-layer buffer they are whatever `engine->GetData(tx, flow,
direction)` returns (e.g. the TLS SNI string, HTTP URI, DNS query name). The content
inspection engine is **completely buffer-agnostic** — it only sees a byte slice.

The keyword's `SigMatchCtx *ctx` (really `DetectContentData *`, `DetectPcreData *`,
etc.) holds the pattern, flags, and offset/depth constraints. The inspection engine
reads those while walking the `SigMatchData` array.

### Summary

| Keyword type | Callback used | What it sees |
|---|---|---|
| `ttl`, `flags`, `dsize`, `flow`, `flowbits`, … | `Match` | `Packet *` struct |
| `app-layer-event`, `app-layer-protocol` | `AppLayerTxMatch` | `Flow *`, `alstate`, `txv` |
| `filemagic`, `filesize`, `filename`, … | `FileMatch` | `File *` struct |
| `content`, `pcre`, `isdataat` | *(none)* | `InspectionBuffer` bytes via content inspection engine |

---

## 6. `fast_pattern`

`fast_pattern` is a **content modifier** that influences MPM (multi-pattern matcher)
prefilter selection. It does not route any keyword to a new list.

### Registration

```c
sigmatch_table[DETECT_FAST_PATTERN].flags |= SIGMATCH_OPTIONAL_OPT;
// No SIGMATCH_INFO_STICKY_BUFFER, no SIGMATCH_INFO_CONTENT_MODIFIER
// Match = NULL (it is not a runtime matcher)
```

### Syntax

| Form | Flag Set | Constraints |
|------|----------|-------------|
| `fast_pattern;` | `DETECT_CONTENT_FAST_PATTERN` | none |
| `fast_pattern:only;` | `DETECT_CONTENT_FAST_PATTERN` \| `DETECT_CONTENT_FAST_PATTERN_ONLY` | cannot combine with distance/within/offset/depth on same content |
| `fast_pattern:offset,len;` | `DETECT_CONTENT_FAST_PATTERN` \| `DETECT_CONTENT_FAST_PATTERN_CHOP` | `fp_chop_offset`, `fp_chop_len` stored in `DetectContentData` |

### What Setup() Does

```c
// Finds the most-recently parsed content (highest sm->idx before this keyword)
SigMatch *pm1 = DetectGetLastSMFromMpmLists(de_ctx, s);    // any MPM-capable buffer
SigMatch *pm2 = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);  // any content
// Picks the one with higher idx (most recent)
// Then sets flags on that content's DetectContentData:
cd->flags |= DETECT_CONTENT_FAST_PATTERN;
```

`fast_pattern` applies to the **most recently parsed content before it** — not
necessarily the immediately preceding token. `content:"foo"; content:"bar"; fast_pattern;`
marks `"bar"`, not `"foo"`. Non-content keywords between the content and `fast_pattern`
are ignored for selection purposes (only `idx` order matters).

`fast_pattern` **only** works on `DETECT_CONTENT` — it cannot follow `pcre`,
`isdataat`, or other non-content keywords. It also cannot be used with content in
`base64_data` buffers, and only one `fast_pattern` is allowed per signature.

### How the Engine Uses It

During `SigGroupBuild`, `PatternMatchPrepareGroup()` scans each signature's content
keywords looking for `DETECT_CONTENT_FAST_PATTERN`. When found, `SetMpm()` is called
immediately (early return — no further scoring needed):

```c
if (cd->flags & DETECT_CONTENT_FAST_PATTERN) {
    SetMpm(s, sm, list_id);
    return;
}
```

`SetMpm()` records `s->init_data->mpm_sm = sm` and `s->init_data->mpm_sm_list = list_id`,
and sets `DETECT_CONTENT_MPM` on the content. Without `fast_pattern`, the engine
runs a scoring heuristic (pattern length, rarity, position flags) to pick the best
candidate automatically.

For `fast_pattern:chop`, the MPM is fed only the substring `[fp_chop_offset, fp_chop_offset+fp_chop_len)` of the content, not the full pattern. This is useful when
a long content string has a short, rare prefix worth prefiltering on.

---

## 7. Summary: Which List Does a Keyword Land In?

```
Is init_data->list set to a dynamic ID?
│
├─ YES → keyword goes to buffers[] under that ID
│         (DetectBufferGetActiveList may first replace it with
│          a transforms-derived ID on first content keyword)
│
└─ NO (NOTSET) → keyword uses its own default
                  content/pcre/isdataat → DETECT_SM_LIST_PMATCH → smlists[1]
                  packet keywords     → DETECT_SM_LIST_MATCH   → smlists[0]
                  postmatch keywords  → DETECT_SM_LIST_POSTMATCH → smlists[3]
```

`init_data->list` is set only by:
1. Sticky buffer keyword (`SIGMATCH_INFO_STICKY_BUFFER`) via `SCDetectBufferSetActiveList()`
2. `base64_data` directly
3. Transform consumption inside `DetectBufferGetActiveList()`

It is reset to `NOTSET` by `pkt_data` or implicitly by `SCSigMatchAppendSMToList()`
if a keyword is appended to a different list than the one currently tracked.

---

## 8. Postscript: Why `base64_data` Is Handled Uniquely

`base64_data` gets a hardcoded built-in list ID (`DETECT_SM_LIST_BASE64_DATA = 2`,
slot 2 in `smlists[]`) rather than a dynamic buffer ID like `http.uri` or `tls.sni`.
This is not an accident or legacy quirk — it reflects a fundamental difference in
how the buffer comes into existence.

All normal dynamic buffers correspond to real application-layer data retrieved via
a `GetData()` callback. The buffer *pre-exists* and the engine dispatches content
matches against it during an inspection pass.

`base64_data` has none of that. The buffer **does not exist until `base64_decode`
runs at runtime**. When `DetectBase64DecodeDoMatch()` succeeds during inspection, it
decodes bytes from the *currently-inspected buffer* into `det_ctx->base64_decoded`,
a scratch buffer in the per-thread context. There is no `GetData()`, no registered
buffer type, no separate inspection pass.

The `DETECT_SM_LIST_BASE64_DATA` list is then inspected **inline and recursively**
right at the point where `base64_decode` matched, by an immediate recursive call to
`DetectEngineContentInspectionInternal()`:

```c
// detect-engine-content-inspection.c
} else if (smd->type == DETECT_BASE64_DECODE) {
    if (DetectBase64DecodeDoMatch(det_ctx, s, smd, buffer, buffer_len)) {
        if (s->sm_arrays[DETECT_SM_LIST_BASE64_DATA] != NULL) {
            if (det_ctx->base64_decoded_len) {
                det_ctx->buffer_offset = 0;
                int r = DetectEngineContentInspectionInternal(det_ctx, ctx, s,
                        s->sm_arrays[DETECT_SM_LIST_BASE64_DATA], NULL, f,
                        det_ctx->base64_decoded, det_ctx->base64_decoded_len, 0, ...);
                if (r == 1) {
                    goto final_match;   /* "Base64 is a terminal list." */
                }
            }
        }
    }
}
```

This has two important consequences:

1. **It is terminal.** The comment in the source says it: *"Base64 is a terminal
   list."* On match it jumps to `final_match`, bypassing the rest of the outer
   inspection list. There is no way to return to the outer buffer after
   `base64_data` content matches.

2. **It cannot be switched away from.** `SCDetectBufferSetActiveList()` hard-rejects
   if `list == DETECT_SM_LIST_BASE64_DATA`, and `fast_pattern` explicitly rejects
   content in this list. Both restrictions exist because the base64 context is a
   one-way recursive dive into a scratch buffer, not a peer inspection context that
   the engine can freely switch in and out of.

The built-in list ID is therefore necessary so that `s->sm_arrays[DETECT_SM_LIST_BASE64_DATA]`
is directly addressable at detection time without going through the normal dynamic
buffer dispatch machinery.
