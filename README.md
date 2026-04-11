# masterdns-qs-tunnel

`masterdns-qs-tunnel` is a Go tunnel inspired by `QS-Tunnel` and `MasterDnsVPN`.

The project keeps the asymmetric idea from QS-Tunnel:

- uplink traffic goes out through DNS queries
- downlink traffic comes back through a spoofed UDP path

For uplink speed, the DNS transport style is closer to MasterDnsVPN than the original QS-Tunnel framing. The client builds binary uplink fragments, encodes them with a MasterDns-style lower-base36 transport, and then splits them into DNS labels.

## What it does

- runs as a `client` or `server` CLI
- accepts local UDP traffic on the client side and tunnels it upward through DNS queries
- reassembles the DNS uplink on the server side and forwards it to a UDP upstream
- learns client return metadata from periodic info frames
- sends downstream payloads back either:
  - with raw spoofed IPv4 UDP packets when `use_raw_spoofing=true`
  - or with a normal UDP socket when `use_raw_spoofing=false` for easier local testing

## Downloads

Release binaries are built with GitHub Actions and published on the release page:

[GitHub Releases](https://github.com/blackestwhite/masterdns-qs-tunnel/releases)

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

- raw spoofed replies require infrastructure that can actually transmit spoofed packets
- the current implementation focuses on the UDP relay model
- IPv4 is supported for the spoof metadata and raw spoof sender

## Support The Project

If this project helps people connect to the internet, please consider donating to keep it alive and support further work.

BEP-20 (BNB Chain):

`0x2455B82cEAD31ceC026ae930B932a22Bb994FB76`
