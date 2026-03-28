/**
 * \file
 *
 * \brief Dump parsed rule (Signature) data structures as JSON for debugging.
 *
 * Walks the Signature and its SigMatch lists after parsing, outputting a
 * JSON representation of all internal data structures via SCLogNotice.
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-proto.h"
#include "detect-engine-sigdump.h"
#include "detect-reference.h"
#include "detect-metadata.h"
#include "detect-content.h"
#include "action-globals.h"
#include "app-layer-protos.h"

#include "rust.h"

static const char *SigListNameById(int list)
{
    switch (list) {
        case DETECT_SM_LIST_MATCH:
            return "match";
        case DETECT_SM_LIST_PMATCH:
            return "pmatch";
        case DETECT_SM_LIST_BASE64_DATA:
            return "base64_data";
        case DETECT_SM_LIST_POSTMATCH:
            return "postmatch";
        case DETECT_SM_LIST_TMATCH:
            return "tmatch";
        case DETECT_SM_LIST_SUPPRESS:
            return "suppress";
        case DETECT_SM_LIST_THRESHOLD:
            return "threshold";
        default:
            return "unknown";
    }
}

static void DumpSigFlags(SCJsonBuilder *jb, uint32_t flags)
{
    SCJbOpenArray(jb, "flags");
    if (flags & SIG_FLAG_SRC_ANY)
        SCJbAppendString(jb, "src_any");
    if (flags & SIG_FLAG_DST_ANY)
        SCJbAppendString(jb, "dst_any");
    if (flags & SIG_FLAG_SP_ANY)
        SCJbAppendString(jb, "sp_any");
    if (flags & SIG_FLAG_DP_ANY)
        SCJbAppendString(jb, "dp_any");
    if (flags & SIG_FLAG_FIREWALL)
        SCJbAppendString(jb, "firewall");
    if (flags & SIG_FLAG_DSIZE)
        SCJbAppendString(jb, "dsize");
    if (flags & SIG_FLAG_APPLAYER)
        SCJbAppendString(jb, "applayer");
    if (flags & SIG_FLAG_TXBOTHDIR)
        SCJbAppendString(jb, "txbothdir");
    if (flags & SIG_FLAG_REQUIRE_PACKET)
        SCJbAppendString(jb, "require_packet");
    if (flags & SIG_FLAG_REQUIRE_STREAM)
        SCJbAppendString(jb, "require_stream");
    if (flags & SIG_FLAG_MPM_NEG)
        SCJbAppendString(jb, "mpm_neg");
    if (flags & SIG_FLAG_FLUSH)
        SCJbAppendString(jb, "flush");
    if (flags & SIG_FLAG_REQUIRE_FLOWVAR)
        SCJbAppendString(jb, "require_flowvar");
    if (flags & SIG_FLAG_FILESTORE)
        SCJbAppendString(jb, "filestore");
    if (flags & SIG_FLAG_TOSERVER)
        SCJbAppendString(jb, "toserver");
    if (flags & SIG_FLAG_TOCLIENT)
        SCJbAppendString(jb, "toclient");
    if (flags & SIG_FLAG_TLSSTORE)
        SCJbAppendString(jb, "tlsstore");
    if (flags & SIG_FLAG_BYPASS)
        SCJbAppendString(jb, "bypass");
    if (flags & SIG_FLAG_PREFILTER)
        SCJbAppendString(jb, "prefilter");
    if (flags & SIG_FLAG_SRC_IS_TARGET)
        SCJbAppendString(jb, "src_is_target");
    if (flags & SIG_FLAG_DEST_IS_TARGET)
        SCJbAppendString(jb, "dest_is_target");
    SCJbClose(jb);
}

static void DumpAction(SCJsonBuilder *jb, uint8_t action)
{
    SCJbOpenArray(jb, "action");
    if (action & ACTION_ALERT)
        SCJbAppendString(jb, "alert");
    if (action & ACTION_DROP)
        SCJbAppendString(jb, "drop");
    if (action & ACTION_REJECT)
        SCJbAppendString(jb, "reject");
    if (action & ACTION_REJECT_DST)
        SCJbAppendString(jb, "reject_dst");
    if (action & ACTION_REJECT_BOTH)
        SCJbAppendString(jb, "reject_both");
    if (action & ACTION_PASS)
        SCJbAppendString(jb, "pass");
    if (action & ACTION_CONFIG)
        SCJbAppendString(jb, "config");
    if (action & ACTION_ACCEPT)
        SCJbAppendString(jb, "accept");
    SCJbClose(jb);
}

static const char *IPProtoName(int proto)
{
    switch (proto) {
        case 0: return "HOPOPT";
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 4: return "IPv4-encap";
        case 6: return "TCP";
        case 8: return "EGP";
        case 17: return "UDP";
        case 27: return "RDP";
        case 33: return "DCCP";
        case 41: return "IPv6-encap";
        case 43: return "IPv6-Route";
        case 44: return "IPv6-Frag";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        case 59: return "IPv6-NoNxt";
        case 60: return "IPv6-Opts";
        case 89: return "OSPF";
        case 103: return "PIM";
        case 112: return "VRRP";
        case 132: return "SCTP";
        case 143: return "Ethernet";
        default: return NULL;
    }
}

static void DumpProto(SCJsonBuilder *jb, const DetectProto *proto)
{
    char name[32];
    uint8_t set[256];
    int count = 0;

    SCJbOpenObject(jb, "proto");

    /* collect set protocol numbers */
    for (int i = 0; i < 256; i++) {
        if (proto->proto[i / 8] & (1 << (i % 8))) {
            set[count++] = i;
        }
    }

    /* output as collapsed ranges: "0-255" or "6" or "6,17" or "1,6,17,41-43" */
    SCJbOpenArray(jb, "ip_protos");
    for (int i = 0; i < count; i++) {
        const int start = set[i];
        int end = start;

        while (i + 1 < count && set[i + 1] == end + 1) {
            end = set[++i];
        }

        if (start == end) {
            const char * const pname = IPProtoName(start);

            if (pname) {
                SCJbAppendString(jb, pname);
            } else {
                snprintf(name, sizeof(name), "%d", start);
                SCJbAppendString(jb, name);
            }
        } else if (start == 0 && end == 255) {
            SCJbAppendString(jb, "any");
        } else {
            snprintf(name, sizeof(name), "%d-%d", start, end);
            SCJbAppendString(jb, name);
        }
    }
    SCJbClose(jb); /* ip_protocols */

    /* decode proto flags */
    SCJbOpenArray(jb, "flags");
    if (proto->flags & DETECT_PROTO_ANY)
        SCJbAppendString(jb, "any");
    if (proto->flags & DETECT_PROTO_ONLY_PKT)
        SCJbAppendString(jb, "only_pkt");
    if (proto->flags & DETECT_PROTO_ONLY_STREAM)
        SCJbAppendString(jb, "only_stream");
    if (proto->flags & DETECT_PROTO_IPV4)
        SCJbAppendString(jb, "ipv4");
    if (proto->flags & DETECT_PROTO_IPV6)
        SCJbAppendString(jb, "ipv6");
    SCJbClose(jb); /* flags */

    SCJbClose(jb); /* proto */
}

static void DumpReferences(SCJsonBuilder *jb, const DetectReference *ref)
{
    SCJbOpenArray(jb, "references");
    for (const DetectReference *r = ref; r != NULL; r = r->next) {
        SCJbStartObject(jb);
        if (r->key)
            SCJbSetString(jb, "key", r->key);
        if (r->reference)
            SCJbSetString(jb, "reference", r->reference);
        SCJbClose(jb);
    }
    SCJbClose(jb);
}

static void DumpMetadata(SCJsonBuilder *jb, const DetectMetadataHead *meta)
{
    if (meta == NULL)
        return;
    SCJbOpenArray(jb, "metadata");
    for (const DetectMetadata *m = meta->list; m != NULL; m = m->next) {
        SCJbStartObject(jb);
        if (m->key)
            SCJbSetString(jb, "key", m->key);
        if (m->value)
            SCJbSetString(jb, "value", m->value);
        SCJbClose(jb);
    }
    SCJbClose(jb);
}

static void DumpSigMatchList(
        SCJsonBuilder *jb, const char *list_name, const SigMatch *sm_list)
{
    SCJbOpenArray(jb, list_name);
    for (const SigMatch *sm = sm_list; sm != NULL; sm = sm->next) {
        SCJbStartObject(jb);
        const char * const kw_name = sigmatch_table[sm->type].name;

        if (kw_name) {
            SCJbSetString(jb, "type", kw_name);
        } else {
            SCJbSetInt(jb, "type_id", (int64_t)sm->type);
        }

        if (sm->ctx != NULL) {
            SCJbOpenObject(jb, "data");
            if (sigmatch_table[sm->type].DumpJSON != NULL) {
                sigmatch_table[sm->type].DumpJSON(sm->ctx, jb);
            } else if (sm->ctx != NULL) {
                SCJbSetBool(jb, "todo", true);
            }
            SCJbClose(jb);
            /* jq query to select out all "type" where "todo" is true:
             * .init_data.smlists[][] | select(.data.todo == true) | .type
             */
        }

        SCJbClose(jb); /* sm object */
    }
    SCJbClose(jb); /* list array */
}

static void DumpBuffers(SCJsonBuilder *jb, const DetectEngineCtx *de_ctx,
        const SignatureInitData *init_data)
{
    if (init_data->buffer_index == 0)
        return;

    SCJbOpenArray(jb, "buffers");
    for (uint32_t i = 0; i < init_data->buffer_index; i++) {
        const SignatureInitDataBuffer *buf = &init_data->buffers[i];
        SCJbStartObject(jb);

        const char *name = DetectEngineBufferTypeGetNameById(de_ctx, (int)buf->id);
        if (name) {
            SCJbSetString(jb, "buffer", name);
        } else {
            SCJbSetUint(jb, "buffer_id", (uint64_t)buf->id);
        }
        SCJbSetBool(jb, "multi_capable", buf->multi_capable);
        SCJbSetBool(jb, "only_tc", buf->only_tc);
        SCJbSetBool(jb, "only_ts", buf->only_ts);

        /* dump transforms applied to this buffer */
        const DetectBufferType *bt = DetectEngineBufferTypeGetById(de_ctx, (int)buf->id);
        if (bt != NULL && bt->transforms.cnt > 0) {
            SCJbOpenArray(jb, "transforms");
            for (int t = 0; t < bt->transforms.cnt; t++) {
                int xid = bt->transforms.transforms[t].transform;
                const char *xname = sigmatch_table[xid].name;
                if (xname) {
                    SCJbAppendString(jb, xname);
                } else {
                    char tmp[16];
                    snprintf(tmp, sizeof(tmp), "%d", xid);
                    SCJbAppendString(jb, tmp);
                }
            }
            SCJbClose(jb); /* transforms */
        }

        /* dump the SigMatch list in this buffer */
        DumpSigMatchList(jb, "matches", buf->head);

        SCJbClose(jb); /* buffer object */
    }
    SCJbClose(jb); /* buffers array */
}

static void DumpMpm(SCJsonBuilder *jb, const DetectEngineCtx *de_ctx,
        const SignatureInitData *init_data)
{
    SCJbOpenObject(jb, "mpm");

    if (init_data->mpm_sm != NULL) {
        const char *kw_name = sigmatch_table[init_data->mpm_sm->type].name;

        if (kw_name) {
            SCJbSetString(jb, "keyword", kw_name);
        } else {
            SCJbSetInt(jb, "keyword_id", (int64_t)init_data->mpm_sm->type);
        }

        /* resolve the list name */
        if (init_data->mpm_sm_list < DETECT_SM_LIST_MAX) {
            SCJbSetString(jb, "sm_list_name", SigListNameById(init_data->mpm_sm_list));
        } else {
            const char *name =
                    DetectEngineBufferTypeGetNameById(de_ctx, init_data->mpm_sm_list);

            if (name) {
                SCJbSetString(jb, "sm_list_name", name);
            } else {
                SCJbSetInt(jb, "sm_list_id", (int64_t)init_data->mpm_sm_list);
            }
        }

        /* if it's a content pattern, dump the selected pattern */
        if (init_data->mpm_sm->type == DETECT_CONTENT && init_data->mpm_sm->ctx != NULL) {
            const DetectContentData *cd = (const DetectContentData *)init_data->mpm_sm->ctx;
            SCJbSetPrintAsciiString(jb, "pattern", cd->content, cd->content_len);
            SCJbSetHex(jb, "pattern_hex", cd->content, cd->content_len);
        }
    } else {
        SCJbSetBool(jb, "set", false);
    }

    assert(init_data->prefilter_sm == NULL);

    SCJbClose(jb); /* mpm */
}


static FILE *out_file;


/**
 * \brief Dump a parsed Signature as JSON to a file stream.
 *
 * Call this after SigInit() succeeds, while init_data is still available.
 */
void SigDumpJSON(const DetectEngineCtx *de_ctx, const Signature *s)
{
    SCJsonBuilder *jb = SCJbNewObject();
    if (jb == NULL) {
        SCLogError("failed to create JSON builder for dumping signature %u", s->id);
        return;
    }

    /* top-level fields */
    SCJbSetUint(jb, "sid", (uint64_t)s->id);
    // SCJbSetUint(jb, "gid", (uint64_t)s->gid);
    SCJbSetUint(jb, "rev", (uint64_t)s->rev);
    SCJbSetInt(jb, "priority", (int64_t)s->prio);
    if (s->msg)
        SCJbSetString(jb, "msg", s->msg);
    if (s->class_msg)
        SCJbSetString(jb, "classtype", s->class_msg);
    SCJbSetUint(jb, "class_id", (uint64_t)s->class_id);
    if (s->sig_str)
        SCJbSetString(jb, "raw", s->sig_str);
    if (s->alproto) {
        SCJbSetString(jb, "alproto", AppProtoToString(s->alproto));
    }

    DumpAction(jb, s->action);
    DumpSigFlags(jb, s->flags);
    DumpProto(jb, &s->proto);

    if (s->init_data) {
        SignatureInitData * const init = s->init_data;

        SCJbOpenObject(jb, "init_data");

        /* init_flags */
        SCJbSetUint(jb, "init_flags", (uint64_t)init->init_flags);

        /* built-in SigMatch lists */
        SCJbOpenObject(jb, "smlists");
        for (int i = 0; i < DETECT_SM_LIST_MAX; i++) {
            if (init->smlists[i] != NULL) {
                DumpSigMatchList(jb, SigListNameById(i), init->smlists[i]);
            }
        }
        SCJbClose(jb); /* smlists */

        /* dynamic buffers */
        DumpBuffers(jb, de_ctx, init);

        /* transforms + hooks should not yet be set */
        assert(init->transforms.cnt == 0);
        assert(init->hook.type == SIGNATURE_HOOK_TYPE_NOT_SET);

        /* MPM (fast pattern) selection */
        DumpMpm(jb, de_ctx, init);

        SCJbClose(jb); /* init_data */
    }

    /* references */
    if (s->references)
        DumpReferences(jb, s->references);

    /* metadata */
    if (s->metadata)
        DumpMetadata(jb, s->metadata);

    SCJbClose(jb); /* root object */

    const uint8_t * const buf = SCJbPtr(jb);

    if (out_file && buf) {
        fwrite(buf, 1, SCJbLen(jb), out_file);
        fputc('\n', out_file);
    }

    SCJbFree(jb);
}

void SigDumpInit(const char *filename)
{
    if (out_file && out_file != stdout) {
        fclose(out_file);
        out_file = NULL;
    }

    out_file = (filename != NULL) ? fopen(filename, "w") : stdout;

    if (out_file == NULL) {
        SCLogError("failed to open file %s for dumping rules", filename);
        return;
    }

    SCLogNotice("Dumping rules to %s",
            (filename) ? filename : "stdout");
}
