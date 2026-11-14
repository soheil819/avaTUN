# Backhaul IP carriers

New web-created Backhaul tunnels use a real Linux TUN link for TCP, TCPMux,
X-TCPMux, WS, WSS, WSMux, WSSMux, X-WSMux and AnyTLS. The selected carrier
is retained in `tun_carrier`; `carrier=tun` identifies the layer-3 link.

The bundled core accepts `transport.type=tun`, `tun.encapsulation=tcp` and
`tun.carrier=tcpmux` (or another supported stream carrier). Mux carriers use an
actual SMUX session with one ordered packet stream per TUN. Carrier selection
is bound into peer authentication. A missing carrier preserves the existing
TUN/TCP wire format. IPX remains a separate raw-IP mode.

The controller's `/api/v1/tunnels/backhaul-pair` checks both endpoints, chooses
an unused interface and a non-overlapping RFC1918 /30 from both network
snapshots, validates both configurations, starts the responder before the
initiator and cleans attempted endpoints after failure. Both peers need this
core version. Legacy service-only tunnels retain their running configuration;
editing one upgrades it to an IP tunnel through the coordinated rebuild path.

Ping, iperf3 and HAProxy use the actual inner peer address through the named
interface. A dummy/loopback address is never presented as a tunnel peer.

The complete offline-buildable core is under `vendor/backhaul/source`:

```
cd vendor/backhaul/source
sh scripts/build.sh
```

Validation:

```
python3 scripts/check-backhaul-ip-pair.py
# Linux root, isolated namespaces; includes bidirectional ping and HAProxy HTTP:
python3 scripts/check-backhaul-carriers-netns.py /path/to/new/backhaul
```

IPX pairs also receive a unique TUN interface, non-overlapping inner /30 and
a free health listener port on each endpoint. Existing raw IPX tunnels can
continue with their saved resources until edited.
