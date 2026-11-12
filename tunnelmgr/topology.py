"""Deterministic node/link and address planning for multi-node Backhaul TUN meshes."""
from __future__ import annotations
import hashlib
import ipaddress
import itertools
import re

ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


def _host(value):
    if not isinstance(value, str) or not value:
        raise ValueError("endpoint host must be a hostname or IP address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not HOST.fullmatch(value) or ".." in value or value.endswith("."):
            raise ValueError(f"invalid endpoint host {value!r}")
        return value


def _link_id(a, b):
    digest = hashlib.sha256(f"{a}\0{b}".encode()).hexdigest()[:8]
    return f"{a[:12]}-{b[:12]}-{digest}"


def mesh_plan(nodes, pool="10.240.0.0/16", topology="full", hub=None,
              direction="direct", public_nodes=None, endpoints=None):
    if not isinstance(nodes, list) or not 2 <= len(nodes) <= 64:
        raise ValueError("mesh requires 2..64 nodes")
    if any(not isinstance(n, str) or not ID.fullmatch(n) for n in nodes):
        raise ValueError("invalid node ID")
    if len(set(nodes)) != len(nodes):
        raise ValueError("node IDs must be unique")
    if topology not in ("full", "hub"):
        raise ValueError("topology must be full or hub")
    if direction not in ("direct", "reverse"):
        raise ValueError("direction must be direct or reverse")
    net = ipaddress.ip_network(pool, strict=True)
    if net.version != 4 or net.prefixlen > 30:
        raise ValueError("overlay pool must be an IPv4 network with room for /30 links")
    if topology == "hub":
        if hub not in nodes:
            raise ValueError("hub must be one of the selected nodes")
        pairs = [(n, hub) for n in nodes if n != hub]
    else:
        if hub is not None:
            raise ValueError("hub is only valid for hub topology")
        pairs = list(itertools.combinations(nodes, 2))
    public = set(public_nodes if public_nodes is not None else nodes)
    if not public.issubset(nodes):
        raise ValueError("public node IDs must be selected mesh nodes")
    if endpoints is None:
        endpoints = {}
    if not isinstance(endpoints, dict) or set(endpoints) - set(nodes):
        raise ValueError("endpoints must map selected node IDs to public host addresses")
    endpoints = {node: _host(host) for node, host in endpoints.items()}
    if len(pairs) > net.num_addresses // 4:
        raise ValueError("overlay pool does not contain enough /30 subnets")

    links = []
    for index, (a, b) in enumerate(pairs):
        subnet = ipaddress.ip_network((int(net.network_address) + index * 4, 30))
        initiator, listener = (a, b) if direction == "direct" else (b, a)
        if listener not in public:
            raise ValueError(
                f"{direction} requires {listener} to be publicly reachable for link {a}<->{b}; "
                "choose the other direction or add a reachable relay"
            )
        link_id = _link_id(a, b)
        listen_port = 18443 + index
        health_port = 19080 + index
        tun_name = f"bh{index:04x}"
        ips = {a: f"{subnet.network_address + 1}/30", b: f"{subnet.network_address + 2}/30"}
        listener_cfg = {
            "id": link_id, "mode": "server", "listen": f"0.0.0.0:{listen_port}",
            "tun_name": tun_name, "tun_local": ips[listener], "tun_remote": ips[initiator],
            "tun_mtu": 1400, "health_port": health_port,
            "secret_file": f"/etc/backhaul/secrets/{link_id}.token",
        }
        remote_host = endpoints.get(listener)
        if remote_host and ":" in remote_host and not remote_host.startswith("["):
            remote_host = f"[{remote_host}]"
        initiator_cfg = {
            "id": link_id, "mode": "client", "peer": f"{remote_host}:{listen_port}" if remote_host else None,
            "tun_name": tun_name, "tun_local": ips[initiator], "tun_remote": ips[listener],
            "tun_mtu": 1400, "health_port": health_port,
            "secret_file": f"/etc/backhaul/secrets/{link_id}.token",
        }
        links.append({
            "id": link_id, "node_a": a, "node_b": b, "subnet": str(subnet),
            "node_a_ip": ips[a], "node_b_ip": ips[b], "initiator": initiator,
            "listener": listener, "listen_port": listen_port,
            "endpoint": endpoints.get(listener), "backhaul_roles": {listener: "server", initiator: "client"},
            "configs": {listener: listener_cfg, initiator: initiator_cfg},
        })
    return {
        "topology": topology, "direction": direction, "nodes": nodes,
        "link_count": len(links), "links": links,
        "ready_to_configure": all(link["endpoint"] for link in links),
        "note": "Each edge is an independent /30 TUN link. This is a deployment plan; it does not install agents, transfer secrets, or change routes.",
    }
