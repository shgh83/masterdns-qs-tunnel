# Setup Guide

This guide explains how to deploy `masterdns-qs-tunnel` in the way the current code actually works.

The current implementation is a UDP tunnel:

- the client accepts local UDP traffic on `relay_listen`
- the client sends that traffic upward inside DNS queries
- the server reassembles the DNS uplink and forwards the payload to a UDP `upstream`
- the server sends UDP replies back to the client either:
  - through normal UDP when `use_raw_spoofing=false`
  - through raw spoofed IPv4 UDP packets when `use_raw_spoofing=true`

## Recommended first deployment

Start with:

- `use_raw_spoofing=false`
- a simple UDP upstream service
- a domain delegated to your server

That gives you a safer first validation path before you try raw spoofing.

## 1. Prepare a server

You need a public server that can receive DNS queries for your tunnel domain.

The server must have:

- a public IPv4 address
- UDP reachability on port `53`, or a port-forward from UDP `53` to the listen port you choose
- a UDP service behind the tunnel, referenced by the server `upstream` field

If you keep `listen` as `:5300`, then you still need public DNS traffic on UDP `53` to reach it, usually by redirecting or forwarding UDP `53` to UDP `5300`.

## 2. Prepare DNS delegation

The client sends DNS queries to resolvers, and those resolvers must be able to reach your server as the authoritative nameserver for the tunnel domain.

Typical records look like this:

- `ns.example.com A 203.0.113.10`
- `t.example.com NS ns.example.com`

Then:

- the client uses `t.example.com` in `send_domains`
- the server uses `t.example.com` in `allowed_domains`
- public resolvers forward queries for `*.t.example.com` to your server

Keep the delegated tunnel domain short if possible, because shorter names leave more space for payload labels.

## 3. Configure the server

Start from [server.example.json](/Users/blackestwhite/Documents/vaults/vault/masterdns-qs-tunnel/configs/server.example.json).

Minimum fields to set:

- `listen`: where the server listens for DNS queries, for example `:5300`
- `allowed_domains`: tunnel suffixes the server will accept, for example `["t.example.com"]`
- `upstream`: UDP service behind the tunnel, for example `127.0.0.1:9000`
- `info_secret`: shared secret used for client return-path info frames

Important:

- `client_id_length` and `offset_width` must match the client
- `use_raw_spoofing=false` is best for first setup
- `reply_ttl` only matters when spoofed raw replies are enabled

## 4. Configure the client

Start from [client.example.json](/Users/blackestwhite/Documents/vaults/vault/masterdns-qs-tunnel/configs/client.example.json).

Minimum fields to set:

- `relay_listen`: local UDP socket applications send traffic to
- `announce_public_ip`: the public IPv4 address the server should send replies toward
- `spoof_source_ip`: IPv4 source address the server should use when raw spoofing is enabled
- `spoof_source_port`: source port the server should use when raw spoofing is enabled
- `info_secret`: must match the server
- `send_domains`: must match the delegated domain served by the server
- `resolvers` or `resolvers_file`: public resolvers that will carry the DNS uplink

Important:

- `send_domains` must line up with `allowed_domains`
- `announce_public_ip` should be the real public client IP the server can reach
- if `announce_receive_port` is `0`, the client advertises the actual bound `downlink_bind` port automatically
- `duplication` sends the same DNS query to multiple resolvers per fragment; keep it low at first

## 5. Start an upstream UDP service

The current server forwards uplink payloads to a UDP `upstream`, not a TCP service and not a SOCKS server.

Examples of upstreams you can test with:

- a UDP echo service
- a UDP proxy
- a UDP-based VPN or transport component you are experimenting with

For an easy first test, use a UDP echo server on the server host and point `upstream` at it.

## 6. Start the server

```bash
./masterdns-qs-tunnel server -config configs/server.example.json
```

Or from source:

```bash
go run ./cmd/masterdns-qs-tunnel server -config configs/server.example.json
```

## 7. Start the client

```bash
./masterdns-qs-tunnel client -config configs/client.example.json
```

Or from source:

```bash
go run ./cmd/masterdns-qs-tunnel client -config configs/client.example.json
```

## 8. Test the tunnel

Send UDP traffic to the client `relay_listen` address.

A practical first test is:

- run a UDP echo server as the server `upstream`
- send a UDP packet to the client `relay_listen`
- confirm the packet reaches the upstream and that the reply returns to the client

## 9. Only after that, try raw spoofing

When the non-spoofed path works, you can experiment with:

- `use_raw_spoofing=true`
- infrastructure that actually permits crafted IPv4 packets
- a correct `announce_public_ip`
- a correct `spoof_source_ip` and `spoof_source_port`

You should expect raw spoofing to be the highest-risk part of the deployment.

## Common mistakes

- `send_domains` and `allowed_domains` do not match
- the delegated NS records do not point to the server actually receiving tunnel queries
- the server is listening on `:5300`, but public UDP `53` is not forwarded there
- `info_secret` differs between client and server
- `announce_public_ip` is wrong
- a resolver is used that does not forward your delegated zone properly
- the server `upstream` is not UDP

