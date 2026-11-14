<!-- ir_spoof / https://t.me/ir_spoof -->
# Native Linux acceptance report

The independently rebuilt Linux amd64 application passed the recorded acceptance checks below. Both tunnel endpoints used this reconstruction. These results do not establish original proprietary wire compatibility or byte-identical behavior.

| Acceptance | Passed |
| --- | ---: |
| Native Go top-level tests | 54 |
| Native manager tests | 28 |
| Ordinary transport and TCP-TUN cases | 14 |
| Raw IPX cases | 15 |
| Actual installer/systemd steps | 12 |

No native tests were skipped. Go 1.27.2 built the supplied vendor tree offline; the native core is byte-equal to the independently cross-built core. The admitted code file set and its hashes are unchanged.

- Core SHA-256: `2985f51360474f4ad1a3c0ed03fdca52aca0aa9c77d0568f9849376944c8bc48`
- Admitted code SHA-256: `c931aea0e069e7dd50002a2b3666cc7852ae9bc9a1fd8c1de296cdaaa45603fa`
- Native source admission archive SHA-256: `dbabd6697ebe16e4bd2720382922fde30a7152177058b2b7c8d0eae9d21038d4`

Native Go package counts: config 4, core 9, ipx 12, transport 14, tun 5, wire 10.

The matrix ran two peers in separate owned network namespaces inside a disposable VM with no network adapter. The production installer and real systemd services were additionally exercised through loopback.

## Ordinary transport and TUN results

| Case | Result |
| --- | --- |
| `tcp` | Passed |
| `tcpmux` | Passed |
| `xtcpmux` | Passed |
| `ws` | Passed |
| `wss` | Passed |
| `wsmux` | Passed |
| `wssmux` | Passed |
| `xwsmux` | Passed |
| `anytls` | Passed |
| `assigned-source-bind` | Passed |
| `multiple-endpoints-reconnect` | Passed |
| `wrong-secret-refused` | Passed |
| `untrusted-tls-refused` | Passed |
| `tun-tcp` | Passed |

Positive ordinary transport cases checked one-MiB TCP echo, fragmented writes, eight concurrent streams and a response generated only after request EOF. TCP also checked UDP payloads of 0, 1, 32, 1400, 16000 and 60000 bytes. Separate cases checked an assigned source address, secondary endpoint/reconnect, wrong-secret refusal, TLS trust refusal and bidirectional TCP-TUN traffic.

## IPX results

| Case | Algorithm | Result |
| --- | --- | --- |
| `ipx-icmp-aes256-assigned-source` | `aes-256-gcm` | Passed |
| `ipx-icmp-aes256-paired-spoof` | `aes-256-gcm` | Passed |
| `ipx-ipip-aes256-assigned-source` | `aes-256-gcm` | Passed |
| `ipx-ipip-aes256-paired-spoof` | `aes-256-gcm` | Passed |
| `ipx-tcp-aes256-assigned-source` | `aes-256-gcm` | Passed |
| `ipx-tcp-aes256-paired-spoof` | `aes-256-gcm` | Passed |
| `ipx-udp-aes256-assigned-source` | `aes-256-gcm` | Passed |
| `ipx-udp-aes256-paired-spoof` | `aes-256-gcm` | Passed |
| `ipx-gre-aes256-assigned-source` | `aes-256-gcm` | Passed |
| `ipx-gre-aes256-paired-spoof` | `aes-256-gcm` | Passed |
| `ipx-bip-aes256-assigned-source` | `aes-256-gcm` | Passed |
| `ipx-bip-aes256-paired-spoof` | `aes-256-gcm` | Passed |
| `ipx-bip-aes128-paired-spoof` | `aes-128-gcm` | Passed |
| `ipx-bip-chacha-paired-spoof` | `chacha20-poly1305` | Passed |
| `ipx-bip-extra-assigned-source` | `aes-256-gcm` | Passed |

Every IPX profile checked bidirectional ping, one-MiB TCP echo and UDP payloads of 0, 1, 1400, 16000 and 60000 bytes. TUN MTU 1400 with outer MTU 1320 forced application fragmentation. Paired spoof cases used two TUN queues; ordinary cases used one. AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 were exercised, using 100000 PBKDF2 iterations. The additional assigned-source case also checked userspace TCP/UDP mappings through the peer TUN.

Packet headers showed all six distinct IPv4 carriers: ICMP 1, IPIP 4, TCP 6, UDP 17, GRE 47 and BIP 58. This reconstruction uses fresh authenticated framing at both endpoints; the original unsafe IPX nonce construction is not reproduced.

## Installer and service results

The actual offline installer rejected incorrect checksums before mutation, installed the accepted core, created/enabled/started two production services, passed health and data checks, retained a half-close response, survived client restart and assigned-source changes, rejected a damaged update without disrupting working services, and deleted only its owned service/configuration files while preserving an unrelated service.

## Capture scope and privacy

58 exported captures passed the independent destination audit: 133829 observed packets; zero destinations outside the permitted lab network classes. IPv4, IPv6 and ARP targets were evaluated. Captures are bounded traffic samples; their snapshot lengths can truncate payloads. This is not a claim of complete packet coverage or inspection of encrypted payloads.

Raw captures, keys, configurations, private logs and workstation paths are not included in this report. Final release archive contents and personal-information checks require the separate post-packaging privacy audit; this protocol report does not replace that audit.

## Original sample observations

The supplied original binary had five separate short offline CLI observations as an unprivileged user, with additional empty network namespaces and bounded cgroups. The supplied installer was statically decoded and was not executed. These observations are separate from reconstruction acceptance and do not certify that the original is malware-free or establish absence of hidden behavior.

See [machine-readable results](test-results.json), [core description](core.md), [security](security.md) and [documented differences](limits.md).

Attribution: **ir_spoof** — https://t.me/ir_spoof
