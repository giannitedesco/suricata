# Suricata Rule Matching Internals

This document describes how a rule is evaluated at runtime — what data is inspected,
in what order, and when a rule is considered to have matched. Rule head matching
(IP/port/address lookup) is outside the scope of this document.

---

## 1. Signature Types

After parsing and `SigGroupBuild`, each signature is classified into a type that
determines which matching pipeline handles it:

| Type | Description |
|------|-------------|
| `SIG_TYPE_IPONLY` | Only IP src/dst checks; handled by the IPOnly engine |
| `SIG_TYPE_PDONLY` | Packet detection only (no payload) |
| `SIG_TYPE_DEONLY` | Decoder-event only rules |
| `SIG_TYPE_PKT` | Packet-level rules: `sm_arrays[MATCH]` and/or `sm_arrays[PMATCH]` |
| `SIG_TYPE_PKT_STREAM` | Packet + stream payload |
| `SIG_TYPE_APPLAYER` | App-layer but not per-tx (e.g. alproto match only) |
| `SIG_TYPE_APP_TX` | Per-transaction app-layer inspection via `app_inspect` engine list |

At build time, two linked lists are attached to each signature:

- **`s->pkt_inspect`** — a `DetectEnginePktInspectionEngine` chain for packet-level
  matching (`DETECT_SM_LIST_MATCH` and `DETECT_SM_LIST_PMATCH`). Built by
  `DetectEnginePktInspectionSetup()`.
- **`s->app_inspect`** — a `DetectEngineAppInspectionEngine` chain for per-tx
  app-layer buffer matching. Built by `DetectEngineAppInspectionEngineRegister()`.
  Entries are sorted by tx progress, with the MPM/prefilter engine first.

A `SIG_TYPE_APP_TX` rule has **both** — `pkt_inspect` is evaluated first (packet
header + PMATCH), then `app_inspect` engines for each transaction.

---

## 2. The Per-Packet Pipeline: `DetectRun()`

Every packet passes through `DetectRun()` in `detect.c`. Ignoring firewall policy
and IPOnly, the sequence for a normal IDS rule is:

```
DetectRun(packet):
  1. DetectRunGetRuleGroup()        → select SigGroupHead (SGH) by src/dst/port
  2. DetectRunPrefilterPkt()        → run MPM + other prefilters; populate match_array
  3. DetectRulePacketRules()        → evaluate packet-type rules from match_array
  4. DetectRunFrames()              → evaluate frame-type rules (if TCP/UDP + frames)
  5. DetectRunTx()                  → evaluate app-layer/tx rules
  6. DetectRunPostRules()           → finalize alerts
```

Steps 3, 4, 5 are independent: a packet may fire rules from all three.

---

## 3. Prefilter: MPM as a Gate

Before any per-rule evaluation, the prefilter runs:

```c
// detect.c:598
Prefilter(det_ctx, sgh, p, flow_flags, p->sig_mask);
```

The prefilter runs all registered prefilter engines for the SGH — including the
MPM engine (multi-pattern matching against the fast-pattern content of every rule
in the group). It produces `det_ctx->pmq.rule_id_array[]`: a deduplicated list of
rule IDs whose fast-pattern content was found somewhere in the relevant data
(packet payload, or nothing for pure packet rules).

For **packet rules** this runs against raw packet payload (or reassembled stream
data). For **tx rules** a separate `DetectRunPrefilterTx()` runs per-transaction
against each buffer.

The match array built from the PMQ is **not filtered by the fast-pattern location**:
it is a hint that the rule *might* match. Full per-rule evaluation still applies
all constraints (offsets, distances, etc.).

---

## 4. Packet Rule Evaluation: `DetectRulePacketRules()`

Iterates `det_ctx->match_array[]`. For each candidate signature:

1. **Skip** if `s->app_inspect != NULL` (it's an app-tx rule, handled by `DetectRunTx`)
2. **Skip** if `s->frame_inspect != NULL` (handled by `DetectRunFrames`)
3. **`sig_mask` check** — a bitmask fast-check on packet properties (e.g. has
   payload, has flow, has app-layer events). If the signature's mask bits aren't
   set on the packet, skip.
4. **dsize prefilter** — quick check on payload length vs `dsize` keyword
5. **alproto check** — if sig has `SIG_FLAG_APPLAYER`, verify the flow's alproto
   matches
6. **`DetectRunInspectRuleHeader()`** — IP version, L4 protocol, src/dst ports,
   src/dst addresses. (This is the rule head, noted here for completeness.)
7. **`DetectEnginePktInspectionRun()`** — walks `s->pkt_inspect` and calls each
   engine's callback. **This is where `DETECT_SM_LIST_MATCH` and
   `DETECT_SM_LIST_PMATCH` are evaluated.**
8. **`DetectRunPostMatch()`** — if the rule matched, runs `DETECT_SM_LIST_POSTMATCH`
   (flowbits set, flowint increment, tag, etc.). Postmatch actions always run;
   their return values are ignored.

All of steps 1–7 are AND-logic: a single failure short-circuits to `next`.

---

## 5. Packet Inspection Engines: `s->pkt_inspect`

`DetectEnginePktInspectionRun()` iterates `s->pkt_inspect` and calls each
engine's callback in order. All must return `DETECT_ENGINE_INSPECT_SIG_MATCH`
or the rule fails.

`DetectEnginePktInspectionSetup()` builds this list during `SigGroupBuild`:

```c
// detect-engine.c:1861
if (s->sm_arrays[DETECT_SM_LIST_PMATCH] && !state_match_rule)
    → append DetectEngineInspectRulePayloadMatches   // PMATCH
if (s->sm_arrays[DETECT_SM_LIST_MATCH])
    → append DetectEngineInspectRulePacketMatches    // MATCH
```

Note the ordering: **PMATCH is evaluated before MATCH**. (In practice this only
matters if both are present on the same rule, which is unusual.)

### `DETECT_SM_LIST_MATCH` — packet keywords

The callback `DetectEngineInspectRulePacketMatches` runs `sigmatch_table[type].Match()`
on every SigMatch in the list in order. **All must match.** These are keywords like
`ttl`, `flags`, `dsize`, `flow`, `flowbits`, `itype`, `tos`, etc. — they operate
on the packet struct directly, not on payload bytes.

### `DETECT_SM_LIST_PMATCH` — payload / stream keywords

The callback `DetectEngineInspectRulePayloadMatches` handles the `content`/`pcre`/
`isdataat` keywords that apply to the raw payload or TCP stream.

If the signature requires stream data (`SIG_FLAG_REQUIRE_STREAM`):
1. Try **reassembled stream segments** first (`PKT_DETECT_HAS_STREAMDATA`), via
   `DetectEngineInspectStreamPayload()`. If it matches, the alert is tagged
   `PACKET_ALERT_FLAG_STREAM_MATCH`.
2. Fall back to **raw packet payload** if the stream attempt failed, unless the
   sig is stream-only (`SIG_FLAG_REQUIRE_STREAM_ONLY`) or the segment was already
   added to the stream (`PKT_STREAM_ADD`).

If the signature does not require stream data (e.g. `dsize` is used, or it's a
UDP rule), only **raw packet payload** is inspected.

Within a payload inspection, `content` matches run sequentially and all must match.
Relative modifiers (`within`, `distance`, `offset`, `depth`) constrain where the
next match can be found relative to the previous one. The `buffer_offset` in
`det_ctx` is updated after each match to track position. All keywords in the list
must pass for the list to match.

---

## 6. App-Layer / TX Rule Evaluation: `DetectRunTx()`

App-layer rules (`SIG_TYPE_APP_TX`) with `s->app_inspect != NULL` are skipped by
`DetectRulePacketRules()` and evaluated here instead.

### Per-transaction loop

`DetectRunTx()` iterates over **active transactions** in the flow, starting from
the lowest not-yet-inspected transaction ID (`tx_id_min`). For each transaction:

1. **Per-tx MPM prefilter** (`DetectRunPrefilterTx()`) — runs MPM engines against
   each app-layer buffer in the transaction. Produces a candidate rule list for
   this specific transaction, separate from the packet-level PMQ.
2. **Merge with "continue" list** — rules that partially matched on a prior packet
   for this tx are loaded from `tx.de_state` (stored per-tx state).
3. **Merge packet-level prefilter results** — rules that matched at the packet
   level (from `det_ctx->match_array`) are also added as candidates, since an
   app-tx rule also has `pkt_inspect` engines that must pass.
4. **Sort candidates** by signature id.
5. **Evaluate each candidate** via `DetectRunTxInspectRule()`.

### Per-rule evaluation within a transaction: `DetectRunTxInspectRule()`

For a **new** (not continued) inspection:
1. `DetectRunInspectRuleHeader()` — rule head check
2. `DetectEnginePktInspectionRun()` — `pkt_inspect` chain (PMATCH + MATCH keywords
   on the packet). These are evaluated **once per transaction start**, not per
   engine.

Then the `s->app_inspect` engine chain is walked:

```c
const DetectEngineAppInspectionEngine *engine = s->app_inspect;
do {
    if (tx->tx_progress < engine->progress)
        break;            // tx hasn't reached the required state yet → stop, defer
    match = engine->v2.Callback(de_ctx, det_ctx, engine, s, f,
                                flow_flags, alstate, tx_ptr, tx->tx_id);
    if (match == MATCH)  inspect_flags |= BIT_U32(engine->id); total_matches++;
    else                 break;   // failed → rule doesn't match yet
    engine = engine->next;
} while (engine != NULL);

if (engine == NULL && total_matches)
    → DE_STATE_FLAG_FULL_INSPECT → rule matched
```

### App inspection engines and progress

Each `DetectEngineAppInspectionEngine` has a `progress` field (an integer encoding
transaction state progress). The engine list is sorted by progress, with the
MPM/prefilter engine first. If the transaction hasn't reached a required progress
level, the entire rule evaluation **stops and defers** — it will be re-evaluated on
a future packet when the transaction advances.

### Buffer inspection ordering

The `app_inspect` engine chain is built by `DetectEngineAppInspectionEngine2Signature()`
(`detect-engine.c:801`) during `SigGroupBuild`. It iterates over `s->init_data->buffers[]`
in **rule parse order** (left-to-right in the rule text) and inserts each engine via
`AppendAppInspectEngine()` (`detect-engine.c:704`) using the following ordering rules:

1. **MPM/prefilter engine is prepended** — forced to head of list regardless of
   progress or parse position, because it gates the rest of the evaluation.
2. **Lower progress engines sort earlier** — an engine with a lower `progress` value
   is inserted before engines with a higher value.
3. **Same progress → parse order** — when two engines have equal progress (the common
   case: all buffers in the same transaction state), they end up in rule-text order.
   The insertion algorithm appends same-progress engines at the tail of the same-progress
   run, preserving parse order.

**Concrete example** — given a rule with both `tls.sni` and `tls.sni; dotprefix`:

```
tls.sni; content:"foo"; tls.sni; dotprefix; content:"bar";
```

Both buffers have the same `progress` (TLS handshake done). `tls.sni` appears first in
the rule, so its engine is inserted first; `tls.sni + dotprefix` is appended after it.
**Inspection order: `tls.sni` then `tls.sni + dotprefix`.**

If the rule were written with `dotprefix` first, the order would be reversed. The engine
ordering mirrors the rule text.

**`pkt_inspect` engines** (for `DETECT_SM_LIST_PMATCH` and `DETECT_SM_LIST_MATCH`)
are ordered differently — they are not sorted by progress at all. They are built in
`DetectEnginePktInspectionSetup()`: PMATCH (payload) appended before MATCH (packet
fields), regardless of parse order. Both engines are always present if the relevant
SM lists are non-empty.

Each engine's `Callback` fetches a specific buffer for this transaction (e.g. the
HTTP URI, TLS SNI, DNS query name) via the registered `GetData()` function, then
runs `DetectEngineContentInspectionBuffer()` against it — applying all the
`content`/`pcre`/`isdataat` SigMatches in the engine's `sm_list` to the buffer
data.

Each engine corresponds to one **buffer slot** from the rule's `init_data->buffers[]`
(post-SigGroupBuild: one `app_inspect` engine per distinct buffer+transforms used
by the rule). All engines must match for the rule to match.

### State across packets (partial matches)

If a rule's inspection is incomplete at the end of a packet — because the
transaction hasn't reached a required progress stage yet, or because a streaming
buffer isn't complete — the current `inspect_flags` bitmask is stored in
`tx.de_state` (per-transaction detection state). On the next packet touching this
flow, the rule is re-added to the candidate list from the "continue" list, and
inspection resumes from where it left off, skipping already-matched engines
(`inspect_flags & BIT_U32(engine->id)`).

A rule can thus match **across multiple packets** on the same transaction.

---

## 7. Frame Inspection: `DetectRunFrames()`

For protocols that use the frame system (e.g. TLS records, HTTP/2 frames), there
is a third parallel pipeline. Frame rules have `s->frame_inspect != NULL` and are
skipped by both `DetectRulePacketRules()` and `DetectRunTx()`. They are evaluated
by `DetectRunFrames()` against the frames associated with the current packet.

---

## 8. Postmatch: `DetectRunPostMatch()`

Called immediately after a rule matches — whether in the packet pipeline or the tx
pipeline. Runs `sm_arrays[DETECT_SM_LIST_POSTMATCH]` unconditionally (return values
ignored). This list holds side-effect keywords: `flowbits` (set/unset/toggle),
`flowint` (increment/decrement), `tag`, `hostbits`, etc.

---

## 9. Match Semantics Summary

All conditions are **AND**: every component must pass. Short-circuit evaluation
applies — failure at any stage skips the rest.

For a `SIG_TYPE_APP_TX` rule, the full match requires, in order:

```
1. SGH lookup (src/dst/port/proto) — implicit, pre-selection
2. Prefilter (MPM fast-pattern) — candidate gate only; not a definitive check
3. sig_mask bitmask check
4. dsize prefilter
5. DetectRunInspectRuleHeader()   → IP version, L4 proto, ports, addresses
6. DetectEnginePktInspectionRun() → PMATCH (payload) then MATCH (packet keywords)
   [for each tx:]
7. Progress check                 → defer if tx not far enough along
8. app_inspect engines (one per buffer/list):
   → GetData() for the buffer
   → DetectEngineContentInspectionBuffer() → all content/pcre/isdataat in list
   → all engines must match
9. DetectRunPostMatch()           → postmatch side-effects (flowbits, tag, etc.)
```

For a pure packet rule (`SIG_TYPE_PKT`), steps 7–8 are absent. For a stream/payload
rule, step 8 is replaced by PMATCH inspection against packet or stream payload.

The rule is **fully matched** when `engine == NULL && total_matches > 0` at the end
of the `app_inspect` chain walk — meaning every registered engine has set its bit in
`inspect_flags`. For packet rules it is when `DetectEnginePktInspectionRun()`
returns true.

---

## 10. What Data Each List Matches Against

| List / Context | Data source |
|---|---|
| `DETECT_SM_LIST_MATCH` | Packet struct fields (TTL, flags, dsize, flow state, etc.) |
| `DETECT_SM_LIST_PMATCH` | Reassembled stream segments (preferred) or raw packet payload |
| `DETECT_SM_LIST_BASE64_DATA` | Thread-local scratch buffer filled by `base64_decode` mid-inspection |
| `DETECT_SM_LIST_POSTMATCH` | N/A — side effects only, no data |
| Dynamic buffer (app-layer) | Buffer fetched by `engine->GetData(tx, flow, direction)` per tx |
| Dynamic buffer (packet) | Buffer fetched by `engine->GetData(packet)` |
| Dynamic buffer (frame) | Buffer fetched from the frame associated with the packet |
