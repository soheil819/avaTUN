# Linux Tunnel Management System

See [architecture](outputs/architecture-plan-fa.md) and [local run guide](docs/run-local-fa.md). The manager provides a password-based web dashboard, SQLite tunnel and server inventory, SSH-based remote installation and tunnel lifecycle actions, periodic ICMP health probes, and a topology view. Backhaul integration delegates to the supplied **ir_spoof 0.1.0** manager and is not compatible with the original Backhaul wire protocol.

## Start the dashboard

```sh
python3 tunnelmgr/tunnelctl.py init
python3 tunnelmgr/tunnelctl.py account create admin --role admin
./scripts/run-local.sh
```

Passwords are stored with salted scrypt hashes. The browser uses an HttpOnly session cookie. The packaged systemd service listens on all interfaces at port 8765 so the panel can be reached at the server's public IP. The panel currently serves plain HTTP; put it behind TLS before using it over an untrusted network. To keep it loopback-only, set `--host 127.0.0.1` in the service unit and use SSH port forwarding.

The unified tunnel form lists Backhaul TUN, GRE, IPIP, GRETAP, Geneve, VXLAN, ERSPAN, 6to4, ISATAP, GRE/IPIP/SIT FoU, L2TPv3, IPsec/ESP modes, WireGuard, OpenVPN, and OpenConnect. Select direct or reverse for the endpoint role. The WireGuard, OpenVPN, and OpenConnect pair actions create coordinated endpoint configurations with per-side keys/certificates and peer addresses. OpenConnect uses ocserv and a fixed point-to-point `/31` address pair. Add Linux servers with SSH access to install or update the manager and control tunnel endpoints. During enrollment, the SSH password can bootstrap a per-server key and is then discarded; it is never stored. Uploaded or generated SSH keys are stored with mode `0600` under the controller data directory (for the installed service, `/var/lib/tunnelmgr/ssh-keys`). The health worker pings the configured peer through its tunnel interface every ten seconds. ERSPAN is reported as monitor-only because it mirrors traffic instead of carrying a bidirectional IP link.

The **Port forwarding** page manages TCP listeners with HAProxy on the panel server. Install `haproxy` on the controller, then select one or more local tunnel links; each link's peer tunnel IP becomes a backend path, with configurable weight, `leastconn`/`roundrobin`/source-affinity scheduling, and TCP health checks. The destination application must listen on those peer IPs (or on all interfaces). This page does not yet forward to LAN hosts behind a peer or balance arbitrary UDP services.

For a two-ended link, create each endpoint on its server and reverse the local/peer addresses and peer IDs on the other side. The mesh view draws edges when the same tunnel ID is present on both servers; a combined transactional two-server wizard is not yet included.

The routing page can configure paired BGP or OSPF profiles through FRR on both tunnel endpoints. BGP and OSPF export only the explicitly entered private prefixes; port-forward backends on routed remote networks are accepted only when covered by the matching far-side route profile. The routing daemon must be available through the system `frr` package.

The preview installer is `scripts/install-preview.sh`. It installs the web font asset together with the dashboard and installs the service units and protocol runners. Existing accounts created under the former token scheme need a one-time password reset:

```sh
python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account password admin
```

## CLI mesh deployment

`scripts/mesh-deploy.py` can apply a Backhaul TUN mesh to nodes already running the preview. It uses OpenSSH, creates per-link secrets, selects free listener/health ports and TUN interface names, and rolls back created endpoints if an edge fails.
