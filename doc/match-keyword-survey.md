# Suricata Keyword Match-Role Survey

This document classifies every keyword in `keywords.json` into exactly one of five
categories based on how — or whether — it participates in runtime detection.

**A. Non-matching** — no runtime matching role. Covers metadata (sid, rev, msg, …),
parse-time content modifiers (depth, within, nocase, …), sticky-buffer keywords that only
set `init_data->list`, old-style content-modifier aliases (`http_uri`, `http_cookie`, …),
transforms (dotprefix, to_lowercase, pcrexform, xor, …), rule-control keywords (noalert,
prefilter, requires, …), buffer activators (file.data, pkt_data, base64_data), compile-time
protocol filters (ip_proto, l3_proto), and pure side-effect keywords like filestore.

**B. Packet field match** — registers `SigTableElmt.Match(DetectEngineThreadCtx*, Packet*,
const Signature*, const SigMatchCtx*)`.  Matches against packet struct fields at runtime
(ttl, tcp.flags, dsize, flow state, flowbits isset/isnotset, iprep, …).

**C. AppLayerTxMatch field** — registers `SigTableElmt.AppLayerTxMatch(…)`.  Matches
against app-layer transaction fields (integers, enums, flags) without going through the
content-inspection buffer engine.  No `Match` (Packet*) callback.

**D1. Buffer match — direct hardcode** — no `Match` callback; `Setup()` calls
`SCSigMatchAppendSMToList()` with a fixed buffer ID, ignoring `init_data->list` entirely.
Does not require or affect `init_data->list`.

**D2. Buffer match — old-style content modifier** — no `Match` callback; `Setup()` uses
`DetectEngineContentModifierBufferSetup()`, which **hard-rejects if `init_data->list !=
NOTSET`** (completely incompatible with an active sticky buffer — parse error). Finds the
last `content` in `DETECT_SM_LIST_PMATCH` and moves it to the hardcoded target buffer.
`init_data->list` stays `NOTSET` throughout. Reset with `pkt_data;` to use after a sticky
buffer.

**E. Buffer match — active list** — no `Match` callback; evaluated by the
content-inspection engine; `Setup()` reads `s->init_data->list` and appends there,
defaulting to `DETECT_SM_LIST_PMATCH` when `NOTSET`.  The generic content-inspection
family: content, pcre, byte_test, isdataat, bsize, dataset, entropy, …

---

## Category A — Non-matching

### A1. Metadata / rule identity

| Keyword | Notes |
|---------|-------|
| `sid` | rule signature ID |
| `rev` | rule revision |
| `msg` | alert message string |
| `classtype` | classification label |
| `reference` | external reference URL / CVE |
| `gid` | generator ID |
| `priority` | alert priority |
| `target` | marks the target side; sets `SIG_FLAG_DEST_ADDRESS_MATCHED` / `SIG_FLAG_SRC_ADDRESS_MATCHED` |
| `metadata` | arbitrary key-value metadata for logging |

### A2. Parse-time content modifiers (no runtime role)

| Keyword | Notes |
|---------|-------|
| `depth` | sets content match depth bound |
| `within` | sets within-distance bound on previous content |
| `distance` | sets distance from previous content match |
| `offset` | sets start offset for content match |
| `nocase` | makes preceding content case-insensitive |
| `rawbytes` | Snort compat dummy; no effect in Suricata |
| `fast_pattern` | designates MPM prefilter candidate |
| `startswith` | equivalent to `depth:<patlen>` |
| `endswith` | anchors preceding content to buffer end |

### A3. Sticky buffers (set `init_data->list`; no match callback)

| Keyword | Notes |
|---------|-------|
| `ip.src` | raw source IP bytes |
| `ip.dst` | raw destination IP bytes |
| `ipv4.hdr` | raw IPv4 header bytes |
| `ipv6.hdr` | raw IPv6 header bytes |
| `icmpv4.hdr` | raw ICMPv4 header |
| `icmpv6.hdr` | raw ICMPv6 header |
| `tcp.hdr` | raw TCP header |
| `udp.hdr` | raw UDP header |
| `frame` | raw frame buffer |
| `http.uri` | HTTP request URI (decoded) |
| `http.uri.raw` | HTTP request URI (raw) |
| `http.method` | HTTP method |
| `http.protocol` | HTTP version string |
| `http.cookie` | HTTP Cookie header |
| `http.start` | HTTP request/response first line |
| `http.request_body` | HTTP request body (`http_client_body`) |
| `http.response_body` | HTTP response body (`http_server_body`) |
| `http.header` | HTTP headers (normalised) |
| `http.header.raw` | HTTP headers (raw) |
| `http.header_names` | HTTP header name list |
| `http.accept` | HTTP Accept header |
| `http.accept_lang` | HTTP Accept-Language header |
| `http.accept_enc` | HTTP Accept-Encoding header |
| `http.connection` | HTTP Connection header |
| `http.content_len` | HTTP Content-Length header |
| `http.content_type` | HTTP Content-Type header |
| `http.location` | HTTP Location header |
| `http.server` | HTTP Server header |
| `http.referer` | HTTP Referer header |
| `http.user_agent` | HTTP User-Agent header |
| `http.host` | HTTP Host header (normalised) |
| `http.host.raw` | HTTP Host header (raw) |
| `http.stat_code` | HTTP status code buffer |
| `http.stat_msg` | HTTP status message buffer |
| `http.request_line` | full HTTP request line |
| `http.response_line` | full HTTP response line |
| `http.request_header` | individual request header value |
| `http.response_header` | individual response header value |
| `http2.header_name` | HTTP/2 header name |
| `tls.sni` | TLS SNI extension |
| `tls.alpn` | TLS ALPN extension |
| `tls.certs` | TLS certificate chain bytes |
| `tls.cert_issuer` | TLS cert issuer DN text |
| `tls.cert_subject` | TLS cert subject DN text |
| `tls.cert_serial` | TLS cert serial number |
| `tls.cert_fingerprint` | TLS cert SHA1 fingerprint (raw text) |
| `tls.subjectaltname` | TLS Subject Alternative Name |
| `tls.random` | TLS ClientHello/ServerHello random |
| `tls.random_time` | TLS random – time field |
| `tls.random_bytes` | TLS random – bytes field |
| `ja3.hash` | JA3 fingerprint hash |
| `ja3.string` | JA3 fingerprint string |
| `ja3s.hash` | JA3S fingerprint hash |
| `ja3s.string` | JA3S fingerprint string |
| `ja4.hash` | JA4 fingerprint hash |
| `ssh.proto` | SSH banner protocol version |
| `ssh.software` | SSH banner software version |
| `ssh.hassh` | SSH HASSH client fingerprint |
| `ssh.hassh.string` | SSH HASSH client string |
| `ssh.hassh.server` | SSH HASSH server fingerprint |
| `ssh.hassh.server.string` | SSH HASSH server string |
| `dcerpc.stub_data` | DCERPC stub data buffer |
| `smb.named_pipe` | SMB named pipe name |
| `smb.share` | SMB share name |
| `smb.ntlmssp_user` | SMB NTLMSSP username |
| `smb.ntlmssp_domain` | SMB NTLMSSP domain |
| `dnp3.data` | DNP3 application-layer data |
| `krb5.cname` | Kerberos client name |
| `krb5.sname` | Kerberos service name |
| `file.name` | filename extracted from transaction |
| `file.magic` | file magic string |
| `quic.version` | QUIC version field |
| `quic.sni` | QUIC SNI |
| `quic.ua` | QUIC user-agent |
| `ike.init_spi` | IKE initiator SPI |
| `ike.resp_spi` | IKE responder SPI |
| `ike.vendor` | IKE vendor ID |
| `ike.nonce_payload` | IKE nonce payload bytes |
| `ike.key_exchange_payload` | IKE key-exchange payload bytes |
| `dns.query` | DNS query name buffer (alias `dns_query`) |
| `dns.query.name` | DNS query name |
| `dns.queries.rrname` | DNS queries RR name |
| `dns.answers.rrname` | DNS answers RR name |
| `dns.additionals.rrname` | DNS additionals RR name |
| `dns.authorities.rrname` | DNS authorities RR name |
| `dns.response.rrname` | DNS response RR name |
| `dns.answer.name` | individual DNS answer name |
| `mdns.queries.rrname` | mDNS queries RR name |
| `mdns.answers.rrname` | mDNS answers RR name |
| `mdns.additionals.rrname` | mDNS additionals RR name |
| `mdns.authorities.rrname` | mDNS authorities RR name |
| `mdns.response.rrname` | mDNS response RR name |
| `sip.protocol` | SIP protocol string |
| `sip.stat_code` | SIP status code string |
| `sip.stat_msg` | SIP status message |
| `sip.request_line` | SIP request line |
| `sip.response_line` | SIP response line |
| `sip.from` | SIP From header |
| `sip.to` | SIP To header |
| `sip.via` | SIP Via header |
| `sip.user_agent` | SIP User-Agent header |
| `sip.content_type` | SIP Content-Type header |
| `sip.content_length` | SIP Content-Length header |
| `sip.method` | SIP method (`noopt`; sticky buffer, not flagged `sticky-buffer` in JSON) |
| `sip.uri` | SIP URI (`noopt`; sticky buffer) |
| `smtp.helo` | SMTP HELO/EHLO argument |
| `smtp.mail_from` | SMTP MAIL FROM argument |
| `smtp.rcpt_to` | SMTP RCPT TO argument |
| `email.from` | email From field |
| `email.subject` | email Subject |
| `email.to` | email To field |
| `email.cc` | email CC field |
| `email.date` | email Date field |
| `email.message_id` | email Message-ID |
| `email.x_mailer` | email X-Mailer field |
| `email.url` | email URL |
| `email.received` | email Received header |
| `ftp.command` | FTP command buffer (`noopt`; sticky buffer) |
| `ftp.command_data` | FTP command data buffer (`noopt`; sticky buffer) |
| `ftp.reply` | FTP reply buffer (`noopt`; sticky buffer) |
| `ftp.completion_code` | FTP completion code buffer (`noopt`; sticky buffer) |
| `websocket.payload` | WebSocket payload bytes |
| `mqtt.publish.topic` | MQTT publish topic |
| `mqtt.publish.message` | MQTT publish message |
| `mqtt.subscribe.topic` | MQTT subscribe topic |
| `mqtt.unsubscribe.topic` | MQTT unsubscribe topic |
| `mqtt.connect.clientid` | MQTT CONNECT client ID |
| `mqtt.connect.username` | MQTT CONNECT username |
| `mqtt.connect.password` | MQTT CONNECT password |
| `mqtt.connect.willtopic` | MQTT CONNECT will topic |
| `mqtt.connect.willmessage` | MQTT CONNECT will message |
| `mqtt.connect.protocol_string` | MQTT CONNECT protocol name string |
| `rfb.name` | RFB desktop name |
| `ldap.request.dn` | LDAP request DN |
| `ldap.request.attribute_type` | LDAP request attribute type |
| `ldap.responses.dn` | LDAP response DN |
| `ldap.responses.message` | LDAP response message |
| `ldap.responses.attribute_type` | LDAP response attribute type |
| `sdp.session_name` | SDP session name |
| `sdp.session_info` | SDP session info |
| `sdp.origin` | SDP origin |
| `sdp.uri` | SDP URI |
| `sdp.email` | SDP email |
| `sdp.phone_number` | SDP phone number |
| `sdp.connection_data` | SDP connection data |
| `sdp.bandwidth` | SDP bandwidth |
| `sdp.time` | SDP time field |
| `sdp.repeat_time` | SDP repeat time |
| `sdp.timezone` | SDP timezone |
| `sdp.encryption_key` | SDP encryption key |
| `sdp.attribute` | SDP attribute |
| `sdp.media.media` | SDP media descriptor |
| `sdp.media.media_info` | SDP media info |
| `sdp.media.connection_data` | SDP media connection data |
| `sdp.media.encryption_key` | SDP media encryption key |
| `enip.product_name` | EtherNet/IP product name |
| `enip.service_name` | EtherNet/IP service name |
| `quic.cyu.hash` | QUIC CYU hash (`noopt`; sticky buffer) |
| `quic.cyu.string` | QUIC CYU string (`noopt`; sticky buffer) |
| `pgsql.query` | PostgreSQL query text |
| `snmp.usm` | SNMP USM security parameter |
| `snmp.community` | SNMP community string |

### A4. Old-style content-modifier aliases (have `alternative` field)

| Keyword | Notes |
|---------|-------|
| `http_uri` | → `http.uri` |
| `http_raw_uri` | → `http.uri.raw` |
| `http_method` | → `http.method` |
| `http_cookie` | → `http.cookie` |
| `http_client_body` | → `http.request_body` |
| `http_server_body` | → `http.response_body` |
| `http_header` | → `http.header` |
| `http_raw_header` | → `http.header.raw` |
| `http_stat_code` | → `http.stat_code` |
| `http_stat_msg` | → `http.stat_msg` |
| `http_user_agent` | → `http.user_agent` |
| `http_host` | → `http.host` |
| `http_raw_host` | → `http.host.raw` |
| `filename` | → `file.name` |
| `fileext` | → `file.name` (extension variant) |
| `filemagic` | → `file.magic` |
| `uricontent` | → `http.uri`; see also D — Setup calls DetectHttpUriSetup (hardcodes `g_http_uri_buffer_id`) |

### A5. Transforms (modify buffer; no match callback)

| Keyword | Notes |
|---------|-------|
| `dotprefix` | prepends `.` to buffer |
| `to_lowercase` | lowercases buffer |
| `to_uppercase` | uppercases buffer |
| `strip_whitespace` | removes all whitespace from buffer |
| `compress_whitespace` | compresses consecutive whitespace |
| `strip_pseudo_headers` | removes HTTP/2 pseudo-headers |
| `header_lowercase` | lowercases HTTP header names |
| `url_decode` | URL-decodes buffer |
| `to_md5` | replaces buffer with its MD5 hex digest |
| `to_sha1` | replaces buffer with its SHA-1 hex digest |
| `to_sha256` | replaces buffer with its SHA-256 hex digest |
| `domain` | extracts registrable domain from buffer |
| `tld` | extracts TLD from buffer |
| `xor` | XOR-decodes buffer with key (Rust, `has free`; uses `SCDetectSignatureAddTransform`) |
| `from_base64` | base64-decodes buffer (Rust, `has free`) |
| `gunzip` | gzip-decompresses buffer (Rust, `has free`) |
| `zlib_deflate` | zlib-deflate-decompresses buffer (Rust, `has free`) |
| `pcrexform` | PCRE capture-group transform (C, `has free`) |
| `luaxform` | Lua-defined buffer transform (C, `has free`) |

### A6. Buffer activators / rule-control

| Keyword | Notes |
|---------|-------|
| `file.data` | sets `init_data->list` to `file_data` buffer; no match |
| `pkt_data` | resets `init_data->list` to `DETECT_SM_LIST_NOTSET` |
| `base64_data` | sets `init_data->list` to `DETECT_SM_LIST_BASE64_DATA` |
| `noalert` | suppresses alert generation |
| `alert` | forces alert (overrides noalert) |
| `requires` | requires Suricata version or feature at load time |
| `prefilter` | marks a keyword as the prefilter candidate |

### A7. Compile-time protocol filters (removed from match lists before runtime)

| Keyword | Notes |
|---------|-------|
| `ip_proto` | modifies `s->proto.proto` bitmap; SM node removed from `DETECT_SM_LIST_MATCH` by `DetectIPProtoRemoveAllSMs()` before signature finalisation |
| `l3_proto` | sets `s->proto.flags |= DETECT_PROTO_IPV4 / DETECT_PROTO_IPV6`; no SM list entry, no Match callback |

### A8. Side-effect storage (no matching role)

| Keyword | Notes |
|---------|-------|
| `filestore` | appends to `g_file_match_list_id` ("files") and `DETECT_SM_LIST_POSTMATCH`; action is file storage, not detection |

### A9. Obsolete / conditional-compile keywords

| Keyword | Notes |
|---------|-------|
| `ssh.protoversion` | obsolete; Setup always returns error; use `ssh.proto` |
| `ssh.softwareversion` | obsolete; Setup always returns error; use `ssh.software` |
| `geoip` | **conditional**: has `Match` when compiled with MaxMindDB (`HAVE_GEOIP`); in this `keywords.json` export it only has `setup` → treated as A here; see Anomalies |

---

## Category B — Packet Field Match

These keywords register `SigTableElmt.Match(DetectEngineThreadCtx*, Packet*, …)` and
are evaluated against the `Packet*` struct at runtime.

| Keyword | Notes |
|---------|-------|
| `app-layer-protocol` | `DetectAppLayerProtocolPacketMatch`; checks detected app-layer proto against packet |
| `tcp.ack` | TCP acknowledgement number (alias `ack`) |
| `tcp.seq` | TCP sequence number (alias `seq`) |
| `tcp.window` | TCP window size (alias `window`) |
| `tcp.flags` | TCP flag bits (alias `flags`) |
| `tcp.mss` | TCP MSS option value |
| `tcp.wscale` | TCP window scale option |
| `ipopts` | IP option presence check |
| `fragbits` | IP fragmentation/reserved bits |
| `fragoffset` | IP fragment offset value |
| `ttl` | IP time-to-live |
| `tos` | IP TOS/DSCP field |
| `itype` | ICMP type |
| `icode` | ICMP code |
| `icmp_id` | ICMP identifier |
| `icmp_seq` | ICMP sequence number |
| `icmpv6.mtu` | ICMPv6 "Packet Too Big" MTU field |
| `dsize` | payload size |
| `sameip` | source IP == destination IP |
| `id` | IP ID field |
| `rpc` | RPC program/version/procedure |
| `ipv4-csum` | IPv4 checksum validity |
| `tcpv4-csum` | TCP-over-IPv4 checksum validity |
| `tcpv6-csum` | TCP-over-IPv6 checksum validity |
| `udpv4-csum` | UDP-over-IPv4 checksum validity |
| `udpv6-csum` | UDP-over-IPv6 checksum validity |
| `icmpv4-csum` | ICMPv4 checksum validity |
| `icmpv6-csum` | ICMPv6 checksum validity |
| `vlan.id` | VLAN tag ID |
| `vlan.layers` | number of VLAN layers |
| `flow` | flow direction, state, and age flags |
| `flow.age` | flow age in seconds |
| `flow.pkts` | total packet count for flow |
| `flow.pkts_toserver` | to-server packet count |
| `flow.pkts_toclient` | to-client packet count |
| `flow.bytes` | total byte count for flow |
| `flow.bytes_toserver` | to-server byte count |
| `flow.bytes_toclient` | to-client byte count |
| `stream_size` | stream (reassembled) size |
| `threshold` | alert-frequency control; has Match for threshold checking |
| `detection_filter` | per-rule alert-rate threshold |
| `flowbits` | set/unset/toggle flow bits; Match handles `isset`/`isnotset` |
| `flowvar` | per-flow variable comparison |
| `flowint` | per-flow integer arithmetic and comparison |
| `hostbits` | per-host bits; Match handles `isset`/`isnotset` |
| `pktvar` | per-packet variable comparison |
| `iprep` | IP reputation category/score check |
| `app-layer-event` | `DetectAppLayerEventPktMatch`; checks app-layer event flags on packet |
| `decode-event` | checks decoder event flags (shares engine-event Match) |
| `engine-event` | engine internal event check |
| `stream-event` | stream-layer event check |
| `replace` | IPS payload replacement; Match validates replacement context |
| `tag` | sets packet/session/host tag; has Match callback |
| `tls_store` | `DetectTlsStorePostMatch`; stores TLS certificate to disk (side-effect via POSTMATCH); has Match |
| `config` | `DetectConfigPostMatch`; logging/output configuration side-effect |
| `template2` | developer-only example keyword |
| `bypass` | marks flow for bypass; has Match |
| `nfq_set_mark` | sets Netfilter queue mark (IPS mode) |
| `xbits` | both `Match` (packet) and `AppLayerTxMatch` (tx); see Anomalies |
| `lua` | both `Match` (packet) and `AppLayerTxMatch` (tx); see Anomalies |

---

## Category C — AppLayerTxMatch Field

These keywords register only `SigTableElmt.AppLayerTxMatch(…)`.  They inspect integer,
enum, or flag fields extracted from app-layer transactions (no Packet* match, no buffer
content inspection).

| Keyword | Notes |
|---------|-------|
| `ftpbounce` | FTP PORT command bounce detection |
| `ftp.dynamic_port` | FTP dynamic port number |
| `ftp.mode` | FTP transfer mode (active/passive) |
| `ftp.reply_received` | FTP reply status flag |
| `ftpdata_command` | FTP-data command type |
| `tls.version` | TLS record version field |
| `tls.subject` | TLS cert Subject text (AppLayerTxMatch regex; appends to `g_tls_cert_list_id`) |
| `tls.issuerdn` | TLS cert IssuerDN text (AppLayerTxMatch regex; appends to `g_tls_cert_list_id`) |
| `tls_cert_notbefore` | TLS cert not-before timestamp |
| `tls_cert_notafter` | TLS cert not-after timestamp |
| `tls_cert_expired` | TLS cert expiry flag |
| `tls_cert_valid` | TLS cert validity flag |
| `tls.cert_chain_len` | TLS certificate chain length |
| `ssl_version` | SSL/TLS negotiated version |
| `ssl_state` | SSL/TLS handshake state flags |
| `nfs_procedure` | NFS procedure number |
| `nfs.version` | NFS protocol version |
| `smb.version` | SMB protocol version |
| `dcerpc.iface` | DCERPC interface UUID |
| `dcerpc.opnum` | DCERPC operation number |
| `http2.frametype` | HTTP/2 frame type |
| `http2.errorcode` | HTTP/2 error code |
| `http2.priority` | HTTP/2 priority value |
| `http2.window` | HTTP/2 window size |
| `http2.size_update` | HTTP/2 SETTINGS_HEADER_TABLE_SIZE update |
| `http2.settings` | HTTP/2 settings flags/values |
| `modbus` | Modbus function code / unit ID |
| `dnp3_func` | DNP3 function code |
| `dnp3_ind` | DNP3 internal indication bits |
| `dnp3_obj` | DNP3 object type |
| `krb5_err_code` | Kerberos 5 error code |
| `krb5_msg_type` | Kerberos 5 message type |
| `krb5.ticket_encryption` | Kerberos ticket encryption type |
| `ike.exchtype` | IKE exchange type |
| `ike.chosen_sa_attribute` | IKE chosen SA attribute |
| `ike.key_exchange_payload_length` | IKE key-exchange payload length |
| `ike.nonce_payload_length` | IKE nonce payload length |
| `dhcp.leasetime` | DHCP lease time option |
| `dhcp.rebinding_time` | DHCP rebinding time option |
| `dhcp.renewal_time` | DHCP renewal time option |
| `websocket.opcode` | WebSocket opcode |
| `websocket.mask` | WebSocket mask flag |
| `websocket.flags` | WebSocket flags |
| `cip_service` | CIP service code |
| `enip_command` | EtherNet/IP command code |
| `enip.capabilities` | EtherNet/IP capabilities flags |
| `enip.cip_attribute` | EtherNet/IP CIP attribute |
| `enip.cip_class` | EtherNet/IP CIP class |
| `enip.cip_extendedstatus` | EtherNet/IP CIP extended status |
| `enip.cip_instance` | EtherNet/IP CIP instance |
| `enip.cip_status` | EtherNet/IP CIP status |
| `enip.device_type` | EtherNet/IP device type |
| `enip.identity_status` | EtherNet/IP identity status |
| `enip.product_code` | EtherNet/IP product code |
| `enip.protocol_version` | EtherNet/IP protocol version |
| `enip.revision` | EtherNet/IP revision |
| `enip.serial` | EtherNet/IP serial number |
| `enip.state` | EtherNet/IP state |
| `enip.status` | EtherNet/IP status |
| `enip.vendor_id` | EtherNet/IP vendor ID |
| `mqtt.type` | MQTT control packet type |
| `mqtt.flags` | MQTT packet flags |
| `mqtt.qos` | MQTT QoS level |
| `mqtt.protocol_version` | MQTT protocol version |
| `mqtt.reason_code` | MQTT reason code (v5) |
| `mqtt.connack.session_present` | MQTT CONNACK session-present flag |
| `mqtt.connect.flags` | MQTT CONNECT flags byte |
| `rfb.sectype` | RFB security type |
| `rfb.secresult` | RFB security result |
| `ldap.request.operation` | LDAP request operation type |
| `ldap.responses.operation` | LDAP response operation type |
| `ldap.responses.count` | LDAP response count |
| `ldap.responses.result_code` | LDAP response result code |
| `dns.opcode` | DNS opcode |
| `dns.rcode` | DNS response code |
| `dns.rrtype` | DNS resource-record type |
| `snmp.version` | SNMP version |
| `snmp.pdu_type` | SNMP PDU type |

### C — special: `app-layer-state`

`app-layer-state` superficially resembles a D1 keyword — its `Setup()` appends to a
registered buffer ID (`g_applayer_state_list_id`) — but it is not a content-inspection
buffer keyword. It registers its own `DetectEngineAppInspectionEngine` with a custom
callback (`DetectEngineAptStateInspect`) that never inspects buffer bytes. Instead it
reads the **transaction's progress integer** (`AppLayerParserGetStateProgress()`) and
checks whether it is less than or greater than the value given in the rule:

```
app-layer-state:ts_progress>3;   # tx has passed state 3 in toserver direction
```

The buffer ID is just used as a storage slot so the keyword's `SigMatchData` ends up
in the right `app_inspect` engine chain. At runtime it behaves like a Category C field
check on a transaction property, not like a buffer content match.

---

## Category D1 — Buffer Match, Direct Hardcode

`Setup()` appends directly to a fixed buffer ID regardless of `init_data->list`.

| Keyword | Notes |
|---------|-------|
| `urilen` | hardcodes `g_http_uri_buffer_id` or `g_http_raw_uri_buffer_id` (`,raw` suffix) |
| `asn1` | hardcodes `DETECT_SM_LIST_PMATCH` directly |
| `filemd5` | hardcodes `g_file_match_list_id` ("files" buffer) |
| `filesha1` | hardcodes `g_file_match_list_id` ("files" buffer) |
| `filesha256` | hardcodes `g_file_match_list_id` ("files" buffer) |
| `filesize` | hardcodes `g_file_match_list_id` ("files" buffer) |

---

## Category D2 — Buffer Match, Old-Style Content Modifier

`Setup()` goes through `DetectEngineContentModifierBufferSetup()`. **Hard parse error if
`init_data->list != NOTSET`** — cannot be used while a sticky buffer is active. Use
`pkt_data;` to reset first if needed. Moves the last `DETECT_SM_LIST_PMATCH` content to
the target buffer; `init_data->list` stays `NOTSET`.

| Keyword | Notes |
|---------|-------|
| `uricontent` | sugar for `content:…; http_uri;`; hardcodes `g_http_uri_buffer_id`; also listed in A4 as deprecated alias |
| `tls.fingerprint` | hardcodes `g_tls_cert_fingerprint_list_id`; deprecated alias for `tls.cert_fingerprint` |

---

## Category E — Buffer Match, Active List (`init_data->list`)

These keywords have no `Match` callback; they are evaluated by the content-inspection
engine; `Setup()` reads `s->init_data->list` and routes to the currently active buffer,
defaulting to `DETECT_SM_LIST_PMATCH` when `NOTSET`.

| Keyword | Notes |
|---------|-------|
| `content` | primary byte-pattern keyword; defaults to `PMATCH` |
| `pcre` | PCRE pattern; routes via `init_data->list` |
| `byte_test` | numeric byte-value test |
| `byte_jump` | detection-pointer jump |
| `byte_math` | arithmetic on extracted byte value |
| `byte_extract` | extract N bytes into named variable |
| `dataset` | match buffer against an in-memory dataset |
| `datarep` | reputation scoring against dataset |
| `base64_decode` | decode base64 bytes into `DETECT_SM_LIST_BASE64_DATA`; uses `init_data->list` to determine input buffer |
| `bsize` | buffer size comparison; uses `init_data->list` |
| `isdataat` | tests whether data exists at an offset in the active buffer |
| `absent` | asserts buffer is absent; requires an active buffer (`init_data->list` must not be NOTSET) |
| `entropy` | Shannon-entropy check on buffer content; uses `init_data->list` |

---

## Anomalies / Coherence Notes

### Dual-mode keywords (B + C)

| Keyword | Issue |
|---------|-------|
| `xbits` | registers **both** `Match` (for packet-level `isset`/`isnotset`) **and** `AppLayerTxMatch` (for app-layer transaction context).  Placed in **B** above as primary; C also applies for transaction matching. |
| `lua` | registers **both** `Match` (packet-level Lua script) **and** `AppLayerTxMatch` (app-layer Lua script).  Placed in **B** above; C also applies. |

### Keywords that straddle A / D2

| Keyword | Issue |
|---------|-------|
| `uricontent` | It is an old-style content-modifier alias (A4) **and** its Setup() uses the D2 modifier path to hardcode `g_http_uri_buffer_id`. Listed in A4 with a cross-reference note and in D2. |
| `tls.fingerprint` | Flagged `alternative:"tls.cert_fingerprint"` in `keywords.json`, making it look like an A4 alias, but it has `free` and uses the D2 modifier path → D2. |

### Compile-time keywords that temporarily enter a match list (A but anomalous)

| Keyword | Issue |
|---------|-------|
| `ip_proto` | `Setup()` appends a `SigMatch` to `DETECT_SM_LIST_MATCH` with `Match = NULL`, which would crash the runtime match loop.  It is safe only because `DetectIPProtoRemoveAllSMs()` is called during `SigParseProto()` (in `detect-parse.c`) to strip all `DETECT_IPPROTO` nodes before the signature is finalised.  All protocol filtering is baked into `s->proto.proto` at parse time. |

### Conditionally-compiled keyword

| Keyword | Issue |
|---------|-------|
| `geoip` | Has `Match = DetectGeoipMatch` only when `HAVE_GEOIP` (MaxMindDB) is compiled in; otherwise only `Setup = DetectGeoipSetupNoSupport` exists (which always errors).  In the `keywords.json` used here the keyword appears setup-only → placed in A.  With MaxMindDB it belongs in **B**. |

### Side-effect keywords in B

Several B keywords perform only side-effects (not detection) via their `Match` callback
but still technically satisfy the B definition because they register a `Match(Packet*)`:
`tls_store` (stores certificates), `config` (configures output), `tag` (attaches flow/host
tags), `replace` (rewrites payload), `bypass` (marks flow for bypass), `nfq_set_mark` (sets
NFQ mark).  They are correctly in B by mechanism even if their operational role is
side-effect.

### `tls.subject` / `tls.issuerdn` in C

These two keywords perform text matching (regex on the cert Subject/IssuerDN string) via
`AppLayerTxMatch`, not via the buffer content-inspection engine.  They also call
`SCSigMatchAppendSMToList(..., g_tls_cert_list_id)` so they are registered in the
`g_tls_cert_list_id` SM list, but the actual comparison is driven by the `AppLayerTxMatch`
callback.  Category C is correct by mechanism; the "not buffer bytes" phrasing in the
category definition is slightly loose — these do compare string bytes, but through
`AppLayerTxMatch` rather than `DetectEngineContentInspectionBuffer`.

### `asn1` buffer

`asn1` hardcodes `DETECT_SM_LIST_PMATCH` (the raw-payload list) rather than a
named/registered buffer ID.  It is still category D by definition (hardcoded, ignores
`init_data->list`), but unlike the other D members it targets the raw packet payload rather
than an app-layer buffer.
