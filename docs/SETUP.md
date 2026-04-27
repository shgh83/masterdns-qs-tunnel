# Setup Guide

This guide covers deploying `masterdns-qs-tunnel` for a direct server-to-server test with no NAT involved.

## Architecture

```
[Applications on client server]
        │ SOCKS5 (TCP)
        ▼
[masterdns-qs-tunnel client]
        │ DNS queries (uplink)
        ▼ (via public resolvers → authoritative DNS)
[masterdns-qs-tunnel server]
        │ TCP (direct-dial to destination)
        ▼
[Target service]

[masterdns-qs-tunnel server]
        │ UDP downlink (direct, no spoofing)
        ▼
[masterdns-qs-tunnel client  downlink port]
```

The client provides a local **SOCKS5 proxy** (no external tools needed). The server dials TCP connections directly. No external relay daemon, echo server, or upstream service is required.

---

## What you need

- Two servers with public IPv4 addresses (no NAT required and none assumed)
- A domain name you control, with the ability to add NS records
- Go 1.21+ (to build from source) or a pre-built binary from the releases page

---

## Step 1 — Build or download

Build from source on each machine:

```bash
git clone https://github.com/blackestwhite/masterdns-qs-tunnel
cd masterdns-qs-tunnel
go build -o masterdns-qs-tunnel ./cmd/masterdns-qs-tunnel
```

Or download a pre-built binary from [GitHub Releases](https://github.com/blackestwhite/masterdns-qs-tunnel/releases).

---

## Step 2 — DNS delegation

The client sends DNS queries to public resolvers. For those queries to reach your server, you must delegate a subdomain to it.

Add these records in your DNS control panel (replace IPs and names):

```
ns.example.com.  A    <SERVER-PUBLIC-IP>
t.example.com.   NS   ns.example.com.
```

- `t.example.com` is the tunnel domain — keep it short to maximise payload space in each DNS label.
- Public resolvers will forward queries for `*.t.example.com` to `<SERVER-PUBLIC-IP>` on UDP port 53.

If your server cannot listen on port 53 directly (e.g., another service is running there), forward UDP port 53 → 5300:

```bash
# iptables example
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
```

---

## Step 3 — Server config

Copy and edit:

```bash
cp configs/server.example.json configs/server.json
```

Minimum fields to set:

```json
{
  "listen": ":5300",
  "allowed_domains": ["t.example.com"],
  "info_secret": "choose-a-strong-secret",
  "client_id_length": 7,
  "offset_width": 3,
  "reassembly_timeout": "30s",
  "session_idle_timeout": "2m",
  "use_raw_spoofing": false,
  "reply_ttl": 64
}
```

- `listen` — UDP port the server listens on for tunnel DNS queries.
- `allowed_domains` — must match the client `send_domains`.
- `info_secret` — shared secret; must be identical on client and server.
- `use_raw_spoofing: false` — use plain UDP replies (correct for direct server-to-server, no root required).

No `upstream` field is needed. The server dials TCP directly to whatever destination the SOCKS5 client requests.

---

## Step 4 — Client config

Copy and edit:

```bash
cp configs/client.example.json configs/client.json
```

```json
{
  "socks5_listen": "127.0.0.1:1080",
  "downlink_bind": "0.0.0.0:5301",
  "announce_public_ip": "",
  "info_secret": "choose-a-strong-secret",
  "send_domains": ["t.example.com"],
  "resolvers": ["1.1.1.1:53", "8.8.8.8:53"],
  "client_id_length": 7,
  "offset_width": 3,
  "max_label_len": 63,
  "max_qname_len": 253,
  "query_type": 1,
  "duplication": 1,
  "send_delay": "2ms",
  "info_interval": "20s"
}
```

- `socks5_listen` — local SOCKS5 proxy address; point your applications here.
- `downlink_bind` — UDP port the client listens on for server replies. Use a fixed port (e.g. `0.0.0.0:5301`) so the server can reliably reach it. Make sure this port is reachable from the server (open in firewall).
- `announce_public_ip` — leave empty (`""`) to auto-detect from the outbound network interface. Set it explicitly if the auto-detected IP is wrong.
- `info_secret` — must match the server.
- `send_domains` — must match the server `allowed_domains`.
- `resolvers` — public DNS resolvers that will carry the DNS uplink to your server.

---

## Step 5 — Open firewall ports

On the **server**:
- UDP 5300 (or 53) — incoming tunnel DNS queries

On the **client**:
- UDP 5301 — incoming downlink packets from the server (or whichever port you set in `downlink_bind`)

---

## Step 6 — Start the server

```bash
./masterdns-qs-tunnel server -config configs/server.json
```

Or from source:

```bash
go run ./cmd/masterdns-qs-tunnel server -config configs/server.json
```

Expected output:

```
masterdns-qs-tunnel server listening on :5300
```

---

## Step 7 — Start the client

```bash
./masterdns-qs-tunnel client -config configs/client.json
```

Or from source:

```bash
go run ./cmd/masterdns-qs-tunnel client -config configs/client.json
```

Expected output (with auto-detection):

```
announce_public_ip not set, auto-detected: <your-client-ip>
masterdns-qs-tunnel client started with client_id=<random>
```

---

## Step 8 — Test the tunnel

Use `curl` or any application that supports SOCKS5:

```bash
curl --socks5 127.0.0.1:1080 https://example.com
```

Or configure your browser's proxy settings to use SOCKS5 at `127.0.0.1:1080`.

---

## Common mistakes

| Symptom | Likely cause |
|---|---|
| Client gets no downlink packets | `downlink_bind` port is blocked by firewall on the client |
| DNS queries don't reach server | NS delegation is wrong or UDP 53/5300 is not reachable on the server |
| `info_secret` error or no sessions | Secrets don't match between client and server |
| Auto-detected IP is wrong | Set `announce_public_ip` explicitly to the correct public IP |
| `allowed_domains` mismatch | `send_domains` on client must exactly match `allowed_domains` on server |
| `client_id_length` / `offset_width` mismatch | Both sides must use the same values (defaults: 7 and 3) |

