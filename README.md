# masterdns-qs-tunnel

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/blackestwhite/masterdns-qs-tunnel)

`masterdns-qs-tunnel` is a Go tunnel inspired by `QS-Tunnel` and `MasterDnsVPN`.

DeepWiki uses AI to explain the repository, architecture, and code layout:
[deepwiki.com/blackestwhite/masterdns-qs-tunnel](https://deepwiki.com/blackestwhite/masterdns-qs-tunnel)

The project keeps the asymmetric idea from QS-Tunnel:

- uplink traffic goes out through DNS queries
- downlink traffic comes back through a spoofed UDP path

For uplink speed, the DNS transport style is closer to MasterDnsVPN than the original QS-Tunnel framing. The client builds binary uplink fragments, encodes them with a MasterDns-style lower-base36 transport, and then splits them into DNS labels.

> [!WARNING]
> This project is experimental and can be risky to use.
> DNS tunneling and spoofed packet techniques may be detected, blocked, or treated as suspicious by networks, providers, or governments.
> Misconfiguration can break connectivity, expose traffic patterns, or disrupt networks.
> Raw spoofing mode may violate provider rules or local laws in some jurisdictions.
> Use it only if you understand the operational, legal, and safety risks, and only in environments where you accept responsibility for those risks.

## What it does

- runs as a `client` or `server` CLI — no external daemons or relay tools required
- the **client** exposes a local SOCKS5 proxy; any SOCKS5-capable application can use it immediately
- the client tunnels TCP streams upward through DNS queries, encoded and fragmented into DNS labels
- the **server** reassembles the DNS uplink, dials TCP directly to the requested destination, and relays data back
- the server sends downstream data as plain UDP packets to the client (direct path, no spoofing needed for normal deployments)
- the client auto-detects its public IP when `announce_public_ip` is not set
- optionally supports raw spoofed IPv4 UDP replies (`use_raw_spoofing=true`) for advanced network environments

## Downloads

Release binaries are built with GitHub Actions and published on the release page:

[GitHub Releases](https://github.com/blackestwhite/masterdns-qs-tunnel/releases)

Current release targets:

- Linux `amd64`
- Linux `arm64`
- macOS `amd64`
- macOS `arm64`
- FreeBSD `amd64`
- FreeBSD `arm64`

## Guides

- [Setup guide](docs/SETUP.md)
- [Configuration guide](docs/CONFIGURATION.md)

## Build From Source

```bash
go test ./...
go build ./...
```

## Run

Server:

```bash
go run ./cmd/masterdns-qs-tunnel server -config configs/server.example.json
```

Client:

```bash
go run ./cmd/masterdns-qs-tunnel client -config configs/client.example.json
```

## Config files

- `configs/client.example.json`
- `configs/server.example.json`

You will need to replace the example addresses and domains with real values before using it.

## Notes

- `use_raw_spoofing=false` (the default) works on any server without special privileges and is the recommended starting point
- `use_raw_spoofing=true` requires root / `CAP_NET_RAW` and may be blocked by cloud providers
- IPv4 is required for both ends in the current implementation
- no external relay, VPN daemon, or upstream service is needed — the server dials TCP connections directly

## Support The Project

If this project helps people connect to the internet, please consider donating to keep it alive and support further work.

BEP-20 USDT (BNB Chain):

`0x2455B82cEAD31ceC026ae930B932a22Bb994FB76`
