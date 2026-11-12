<!-- Independent reconstruction by ir_spoof - https://t.me/ir_spoof -->
# Backhaul independent Linux rebuild

An independently written **Go** tunnel core and readable offline service manager
by **ir_spoof**. The supplied premium executable was identified as Go, with
obfuscated symbols and embedded app version `v2.0.0-hotfix8`; its compiler version
could not be recovered.

Run this rebuild on **both endpoints**. It is a functional reconstruction with
intentional privacy and cryptographic changes, not recovered original source,
not a byte-identical binary, and not wire-compatible with the premium core.
Measured coverage belongs in [the test report](docs/test-report.md); the
[limits](docs/limits.md) identify differences from the original.

The app and helper do not make vendor license, public-IP lookup, geolocation,
analytics or automatic update requests. Peer connections and explicitly
configured hostname resolution still use the network. Attribution is text; it
does not initiate a Telegram request.

## Install the built Linux package

The release contains an offline installer, extracted runtime archive, complete
vendored source, checksums and Persian user guides. The manager requires Python
3.11+ and systemd. TUN/IPX also requires `/dev/net/tun`, `iproute2` and the relevant
Linux privileges. It does not automatically install system packages.

Copy the installer to each Linux amd64 host, verify its published checksum, then:

```sh
sudo sh backhaul-ir_spoof-linux-amd64-0.1.0.run
```

An interactive terminal opens the guided manager after installation. To reopen:

```sh
sudo backhaul-manager
```

For the extracted runtime archive, run `sudo sh install.sh`. The runtime's
`scripts/install.sh` verifies `bin/backhaul` against its local checksum manifest.
An embedded checksum detects corruption; obtain the release and its expected
checksum from a source you trust.

## Create a TCP and UDP forward

Here **server A** is the public entry and **client B** hosts the destination
service. B connects to A. Forward mappings belong to A. These are application
roles, not geographic requirements.

On A, generate a fresh shared token without displaying its contents:

```sh
sudo backhaul-manager secret demo --kind token
```

Privately transfer `/etc/backhaul/secrets/demo.token` to the same location on B.
Prepare B's directory with `sudo install -d -m 700 /etc/backhaul/secrets`, use your
existing authenticated file-transfer method, then set the transferred file to
mode `600`. Do not post the token or include it in a public configuration.

On A:

```sh
sudo backhaul-manager create demo --mode server --transport tcp \
  --listen 0.0.0.0:8443 --ports 8080=9000 --accept-udp \
  --secret-file /etc/backhaul/secrets/demo.token --start
```

On B, replace `SERVER_A_IP` with A's reachable address:

```sh
sudo backhaul-manager create demo --mode client --transport tcp \
  --peer SERVER_A_IP:8443 \
  --secret-file /etc/backhaul/secrets/demo.token --start
```

A's TCP/UDP port 8080 now targets B's matching TCP/UDP service on
`127.0.0.1:9000`. That destination service must exist; the tunnel does not create
it. Permit the chosen peer and forwarding ports in your own firewall. The app
does not rewrite global firewall or NAT policy. `--accept-udp` is the dedicated
UDP-over-TCP option for transport `tcp`; routed IP/UDP traffic can instead use
TUN. Remove it if you only need TCP. Original UDP ring/frame/write-timeout
performance fields are compatibility metadata here; the actual direct
forwarding bounds are described in [the limits](docs/limits.md).

```sh
sudo backhaul-manager status demo
sudo backhaul-manager stop demo
sudo backhaul-manager start demo
sudo backhaul-manager restart demo
sudo backhaul-manager delete demo --yes
```

The manager checks the core and candidate configuration before creating a
service. Its files are tracked by hash. To change settings not exposed as a
convenience flag, copy a configuration, edit the copy, stop the tunnel, then use
`create ID --config FILE --replace --start`. Editing an owned live file directly
causes later manager changes to be refused.

## Carriers and source addresses

| Carrier labels | Implemented physical carrier |
| --- | --- |
| `tcp`, `tcpmux`, `xtcpmux` | TCP; mux labels use SMUX sessions |
| `ws`, `wss` | Framed RFC 6455 binary WebSocket, plain TCP or verified TLS |
| `wsmux`, `wssmux` | HTTP Upgrade at `/tunnel`, then an unframed SMUX byte stream |
| `xwsmux` | HTTP Upgrade at `/data`, then an unframed SMUX byte stream |
| `anytls` | Browser-shaped uTLS carrier under Backhaul's label; not the separate AnyTLS application protocol |
| `tun` | Linux TUN over authenticated TCP, or IPX raw IPv4 profiles |

The IPX profiles are `icmp`, `ipip`, `udp`, `tcp`, `gre` and `bip`. Raw TCP has a
TCP header without a kernel TCP connection or carrier retransmission; encrypted
IPIP/GRE payloads are not ordinary kernel tunnel interoperability. See the
[IPX design](internal/ipx/README.md) and [source-address guide](docs/source-ip-fa.txt).

Assigned local source binding is distinct from raw packet spoofing:

```sh
sudo backhaul-manager change-source demo --local-ip ASSIGNED_LOCAL_IP
```

This changes a non-IPX dialer's real local bind address. The IP must already be
assigned to an active interface. Multiple `--local-ip` arguments configure the
source list. It does not assign addresses, change public NAT, or make the peer
anonymous. IPX's explicit `--spoof-source` and `--expected-peer-source` settings
must be coordinated on both endpoints and require a working authorized route.

TLS transports verify the peer certificate by default. Give the TLS server
`--cert FILE --key FILE`, and its client `--ca FILE --sni CERTIFICATE_NAME` when
using a private/self-signed certificate. `--edge HOST_OR_IP` changes the dial
destination for WebSocket clients while retaining the configured peer Host/SNI.
Do not disable verification as a substitute for distributing a trust file.

## Build from source

The source archive contains vendored dependencies. Install Go 1.26+ beforehand;
the validation toolchain is recorded in the final test report (Go 1.27.2 is used
by the build lab). A normal offline build is:

```sh
sh scripts/build.sh
./build/backhaul -version
./build/backhaul -c /path/to/config.toml -check
```

The helper requests `CGO_ENABLED=0`, `-trimpath`, no VCS metadata and no module
network access. The final artifact's actual ELF/linkage inspection is recorded
with validation; the original executable's libc requirement is not a requirement
inferred for this rebuild.

```sh
GOTOOLCHAIN=local GOTELEMETRY=off GOPROXY=off GOSUMDB=off \
  go test -mod=vendor -trimpath -buildvcs=false ./...
python3 scripts/test-manager.py
sha256sum build/backhaul
sudo sh scripts/install.sh --binary build/backhaul --sha256 TRUSTED_BUILD_HASH
```

Replace `TRUSTED_BUILD_HASH` with the independently checked hash of your local
build. Root/network privileges are required for the separate TUN/IPX namespace
tests, not for compiling. See [the Persian build guide](docs/build-fa.txt).

## Documentation and security

- [Simple Persian setup instructions](docs/setup-fa.txt)
- [Assigned source selection and paired IPX spoof settings](docs/source-ip-fa.txt)
- [Build and install from source in Persian](docs/build-fa.txt)
- [How the core works](docs/core.md)
- [Intentional differences and limits](docs/limits.md)
- [Security and original-artifact findings](docs/security.md)
- [Measured test report](docs/test-report.md) and [machine-readable results](docs/test-results.json)

The independent core uses new `BHC4` authenticated sessions and `BHX2` IPX
framing. Local peer secrets are security features, not vendor telemetry. Removing
external collection does not establish that any program is malware-free, and
this custom protocol still benefits from independent review. Original and
modified premium executables, private captures, test secrets and workstation
paths are excluded from the public distribution.

The independent implementation is MIT licensed. Vendored dependencies and Go's
standard library retain their own notices. Credit: **ir_spoof** —
<https://t.me/ir_spoof>.
