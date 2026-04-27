# Configuration Guide

This page documents every JSON config field used by `masterdns-qs-tunnel`.

---

## Client config

Example: [`configs/client.example.json`](../configs/client.example.json)

| Field | Required | Default | Meaning |
|---|---|---|---|
| `socks5_listen` | yes (unless `relay_listen` is set) | `127.0.0.1:1080` | Address the built-in SOCKS5 proxy listens on. Point your applications here. |
| `relay_listen` | yes (unless `socks5_listen` is set) | — | Legacy mode: local UDP address for raw UDP relay traffic. Not needed when using SOCKS5. |
| `downlink_bind` | no | `0.0.0.0:0` | UDP address the client listens on for server replies. Use a fixed port (e.g. `0.0.0.0:5301`) for easier firewall rules. |
| `announce_public_ip` | no | auto-detected | Public IPv4 the server sends downlink UDP packets toward. Leave empty (`""`) to auto-detect from the outbound network interface. Set explicitly if auto-detection gives the wrong result. |
| `announce_receive_port` | no | `0` | Override the advertised downlink port. `0` means advertise the actual port bound by `downlink_bind`. |
| `spoof_source_ip` | no | `0.0.0.0` | IPv4 address the server uses as the **source** address when `use_raw_spoofing=true`. Not needed for plain UDP replies. |
| `spoof_source_port` | no | `0` | Source port the server uses when `use_raw_spoofing=true`. Not needed for plain UDP replies. |
| `info_secret` | yes | — | Shared secret that protects the client return-path info frame. Must match the server. |
| `send_domains` | yes | — | Tunnel domains appended to DNS uplink labels. Must be delegated to the server and listed in the server `allowed_domains`. |
| `resolvers` | yes (unless `resolvers_file` is set) | — | Inline list of DNS resolvers used for the uplink, e.g. `["1.1.1.1:53", "8.8.8.8:53"]`. |
| `resolvers_file` | yes (unless `resolvers` is set) | — | Path to a file of resolver addresses (one per line). Can be combined with `resolvers`. |
| `client_id` | no | random | Explicit client identifier. Auto-generated if omitted. Must be lower-base32 and exactly `client_id_length` chars long if set. |
| `client_id_length` | yes | `7` | Length of the client identifier. Must match `client_id_length` on the server. |
| `offset_width` | yes | `3` | Fragment offset parameter width. Must match the server. |
| `max_label_len` | yes | `63` | Maximum DNS label length for payload labels. Must be `1..63`. |
| `max_qname_len` | yes | `253` | Maximum total query name length budget. Drives fragment sizing. |
| `query_type` | yes | `1` | DNS query type number for uplink requests. `1` = A record. |
| `duplication` | yes | `1` | Number of resolvers each DNS fragment is sent to. `1` is the right starting point. |
| `send_delay` | no | `2ms` | Delay between duplicate sends. Duration string, e.g. `2ms`. |
| `info_interval` | no | `20s` | How often the client re-sends the info frame that tells the server where to send downlink packets. |

### Client notes

- `info_secret` must be identical on client and server.
- `send_domains` must exactly match the server `allowed_domains`.
- `announce_public_ip` auto-detection uses the outbound interface IP. On a multi-homed server, set it explicitly.
- `downlink_bind` should use a fixed port (not `:0`) so firewall rules can be written for it.
- `spoof_source_ip` and `spoof_source_port` are **ignored** when the server runs with `use_raw_spoofing=false`.

---

## Server config

Example: [`configs/server.example.json`](../configs/server.example.json)

| Field | Required | Default | Meaning |
|---|---|---|---|
| `listen` | yes | `:5300` | UDP address for incoming DNS queries. Public DNS traffic on port 53 must reach this port (direct or via port-forward). |
| `allowed_domains` | yes | — | Tunnel domain suffixes the server accepts. Must match the client `send_domains`. |
| `upstream` | no | — | Legacy mode: UDP address of an external service to forward reassembled payloads to. Leave empty to use the built-in direct TCP proxy. |
| `client_id_length` | yes | `7` | Expected client ID length. Must match the client. |
| `offset_width` | yes | `3` | Must match the client. |
| `info_secret` | yes | — | Shared secret used to decode client return-path info frames. Must match the client. |
| `reassembly_timeout` | no | `30s` | How long incomplete DNS fragment sets are kept before being discarded. |
| `session_idle_timeout` | no | `2m` | How long inactive client sessions are kept before cleanup. |
| `use_raw_spoofing` | no | `false` | When `true`, replies are sent as raw spoofed IPv4 UDP packets (requires root / `CAP_NET_RAW`). Use `false` for normal deployments. |
| `reply_ttl` | no | `64` | IP TTL used in spoofed IPv4 reply packets. Only relevant when `use_raw_spoofing=true`. |

### Server notes

- When `upstream` is empty (the default), the server acts as a direct TCP proxy: it dials the destination from `FrameConnect` requests and relays data bidirectionally.
- `use_raw_spoofing=false` is correct for direct server-to-server deployments and requires no special privileges.
- `use_raw_spoofing=true` requires root or `CAP_NET_RAW`, and may not work on providers that drop spoofed packets.

---

## Resolver file format

When using `resolvers_file`, each line may be:

- a bare IP: `1.1.1.1`
- `host:port`: `1.1.1.1:53`
- bracketed IPv6: `[2606:4700:4700::1111]:53`

Blank lines and lines starting with `#` are ignored.

---

## Minimum working configs

**Server** (`configs/server.json`):

```json
{
  "listen": ":5300",
  "allowed_domains": ["t.example.com"],
  "info_secret": "replace-me",
  "client_id_length": 7,
  "offset_width": 3,
  "use_raw_spoofing": false
}
```

**Client** (`configs/client.json`):

```json
{
  "socks5_listen": "127.0.0.1:1080",
  "downlink_bind": "0.0.0.0:5301",
  "info_secret": "replace-me",
  "send_domains": ["t.example.com"],
  "resolvers": ["1.1.1.1:53", "8.8.8.8:53"],
  "client_id_length": 7,
  "offset_width": 3,
  "max_label_len": 63,
  "max_qname_len": 253,
  "query_type": 1,
  "duplication": 1
}
```

Leave `announce_public_ip` out (or set it to `""`) and the client will auto-detect the outbound interface IP.

