# Configuration Guide

This page documents the current JSON config fields used by `masterdns-qs-tunnel`.

## Client config

Source example: [client.example.json](/Users/blackestwhite/Documents/vaults/vault/masterdns-qs-tunnel/configs/client.example.json)

| Field | Required | Meaning |
| --- | --- | --- |
| `relay_listen` | yes | Local UDP address the client listens on for application traffic. |
| `downlink_bind` | no | Local UDP bind address for receiving server replies. `0.0.0.0:0` lets the OS choose a port. |
| `announce_public_ip` | yes | Public IPv4 address the server should send return traffic toward. |
| `announce_receive_port` | no | Override for the advertised receive port. Use `0` to advertise the actual `downlink_bind` port. |
| `spoof_source_ip` | yes | IPv4 source address the server should use when raw spoofing mode is enabled. |
| `spoof_source_port` | yes | Source port the server should use when raw spoofing mode is enabled. |
| `info_secret` | yes | Shared secret used to protect the client return-path info frame. Must match the server. |
| `send_domains` | yes | Tunnel domains appended to DNS uplink labels. Must be delegated to the server and allowed by the server config. |
| `resolvers` | yes, unless `resolvers_file` is set | Inline list of resolvers used for DNS uplink, for example `["1.1.1.1:53"]`. |
| `resolvers_file` | yes, unless `resolvers` is set | Path to a file containing resolvers. Can be used instead of or in addition to `resolvers`. |
| `client_id` | no | Explicit client identifier. If omitted, one is generated automatically. |
| `client_id_length` | yes | Length of the client identifier. Must match the server-side expectation. |
| `offset_width` | yes | Width used by the older offset parameter. Keep it matched with the server even though the uplink framing is now binary-first. |
| `max_label_len` | yes | Maximum DNS label length for payload labels. Must be `1..63`. |
| `max_qname_len` | yes | Maximum total qname length budget used for fragment sizing. |
| `query_type` | yes | DNS query type for the uplink request, for example `1` for `A`. |
| `duplication` | yes | Number of resolvers each fragment is sent to. Higher values improve redundancy and increase traffic. |
| `send_delay` | no | Delay between duplicated sends. Supports duration strings such as `2ms`. |
| `info_interval` | no | How often the client resends the info frame that tells the server where to return traffic. |

## Client config notes

- `info_secret` must be identical on client and server.
- `send_domains` must match the delegated tunnel zone.
- `announce_public_ip` should be the address the server can actually send replies to.
- `duplication=1` is the best place to start.
- If you set `client_id`, it must use the lower-base32 alphabet expected by the code.

## Server config

Source example: [server.example.json](/Users/blackestwhite/Documents/vaults/vault/masterdns-qs-tunnel/configs/server.example.json)

| Field | Required | Meaning |
| --- | --- | --- |
| `listen` | yes | UDP listen address for incoming DNS queries, for example `:5300`. |
| `allowed_domains` | yes | Tunnel domains the server will accept. These must match the client `send_domains`. |
| `upstream` | yes | UDP upstream service that receives reassembled uplink payloads. |
| `client_id_length` | yes | Expected client ID length. Must match the client. |
| `offset_width` | yes | Must match the client. |
| `info_secret` | yes | Shared secret used to decode client return-path info frames. Must match the client. |
| `reassembly_timeout` | no | How long incomplete DNS fragment sets are kept before they are dropped. |
| `session_idle_timeout` | no | How long inactive sessions are kept before cleanup. |
| `use_raw_spoofing` | no | Enables raw spoofed IPv4 UDP replies. Start with `false` unless you know your environment supports it. |
| `reply_ttl` | no | TTL used for spoofed IPv4 replies. Must be `1..255`. |

## Server config notes

- `upstream` is UDP in the current implementation.
- `use_raw_spoofing=true` is the risky mode and requires infrastructure support.
- `listen=:5300` is fine internally, but public DNS traffic still needs to reach that socket.

## Resolver file format

When using `resolvers_file`, the parser accepts:

- single IPs such as `1.1.1.1`
- host:port entries such as `1.1.1.1:53`
- bracketed IPv6 host:port entries
- small prefixes that can be safely expanded

Blank lines and `#` comments are ignored.

## Recommended first configuration

Client:

- `duplication: 1`
- `query_type: 1`
- `announce_receive_port: 0`
- one short `send_domains` entry
- a small set of stable public resolvers

Server:

- `use_raw_spoofing: false`
- `listen: ":5300"`
- a simple UDP echo or other UDP service as `upstream`

