#!/usr/bin/env python3
"""Deploy a Backhaul TUN mesh to Linux nodes reachable over SSH."""
from __future__ import annotations

import os
import argparse
import ipaddress
import json
import secrets
import shlex
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tunnelmgr"))
from topology import mesh_plan  # noqa: E402

REMOTE = r'''import ipaddress,json,os,secrets,socket,subprocess,sys
payload=json.load(sys.stdin)
op=payload["op"]; ident=payload["id"]
def app(action,data):
    code="import sys,json;sys.path.insert(0,'/opt/tunnelmgr/tunnelmgr');import tunnelctl as t;d=json.load(sys.stdin);op=d['op']\nif op=='list':\n out=t.rows()\nelif op=='create':\n out=t.create_instance(d['data'])\nelif op=='status':\n x=t.find(d['id'])\n if not x:raise ValueError('unknown tunnel')\n r=t.privileged({'op':'status','id':d['id']});x['live']=r.get('status',{});x['health']=t.tunnel_health(x);out=x\nelif op=='delete':\n r=t.privileged({'op':'delete','id':d['id']})\n if not r.get('ok'):raise ValueError(r.get('error','delete failed'))\n with t.db() as c:c.execute('DELETE FROM tunnels WHERE id=?',(d['id'],))\n out=r\nprint(json.dumps(out))"
    cmd=["runuser","-u","tunnelmgr","--","env","TUNNELMGR_HOME=/var/lib/tunnelmgr","/usr/bin/python3","-c",code]
    p=subprocess.run(cmd,input=json.dumps({"op":action,**data}),text=True,capture_output=True,timeout=45)
    if p.returncode:raise RuntimeError((p.stderr or p.stdout)[-2000:])
    result=json.loads(p.stdout)
    if isinstance(result,dict) and result.get("error"):raise RuntimeError(result["error"])
    return result
def pick_port(used,start,end,host="0.0.0.0"):
    for port in range(start,end+1):
        if port in used:continue
        s=socket.socket();
        try:s.bind((host,port));return port
        except OSError:pass
        finally:s.close()
    raise RuntimeError("no free port in allocation range")
def create():
    existing=app("list",{})
    if any(x["id"]==ident for x in existing):raise RuntimeError("instance ID already exists on this node: "+ident)
    cfg=payload["config"]
    used_names={x.get("metadata",{}).get("tun_name") for x in existing}
    used_names.update(os.listdir("/sys/class/net"))
    for i in range(65536):
        name="bh%04x"%i
        if name not in used_names:cfg["tun_name"]=name;break
    else:raise RuntimeError("no free interface name")
    used_health={x.get("metadata",{}).get("health_port") for x in existing}
    cfg["health_port"]=pick_port(used_health,19080,25000,"127.0.0.1")
    if cfg["mode"]=="server":
        used_listen=set()
        for x in existing:
            val=x.get("metadata",{}).get("listen","")
            try:used_listen.add(int(val.rsplit(":",1)[1]))
            except (ValueError,IndexError):pass
        cfg["listen"]="0.0.0.0:"+str(pick_port(used_listen,18443,30000))
    secret_path=cfg["secret_file"]
    os.makedirs(os.path.dirname(secret_path),mode=0o700,exist_ok=True)
    fd=os.open(secret_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as f:f.write(payload["secret"]+"\n")
    try:
        cfg.pop("id",None)
        result=app("create",{"data":{"id":ident,**cfg}})
    except Exception:
        try:os.unlink(secret_path)
        except FileNotFoundError:pass
        raise
    return {"ok":True,"config":cfg,"result":result}
def delete():
    result=app("delete",{"id":ident})
    path=payload.get("secret_file")
    if path:
        try:os.unlink(path)
        except FileNotFoundError:pass
    return result
def check():
    item=app("status",{"id":ident})
    peer=item.get("metadata",{}).get("tun_remote","").split("/",1)[0]
    live=item.get("live",{})
    if not live.get("active"):return {"ok":False,"id":ident,"live":live,"ping":False,"peer":peer}
    return {"ok":item.get("health",{}).get("reachable",False),"id":ident,"live":live,"peer":peer,"ping":item.get("health",{}).get("reachable",False)}
try:
    out=create() if op=="create" else delete() if op=="delete" else check()
    print(json.dumps(out))
except Exception as e:
    print(json.dumps({"error":str(e)}));sys.exit(1)
'''


def parse_mapping(value: str, what: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in value.split(","):
        key, sep, val = entry.partition("=")
        if not sep or not key.strip() or not val.strip():
            raise ValueError(f"{what} must use node=value,node=value")
        key, val = key.strip(), val.strip()
        if key in result:
            raise ValueError(f"duplicate {what} entry for {key}")
        result[key] = val
    return result


class NodeSSH:
    def __init__(self, user: str, identity: str | None, control_dir: str):
        self.user, self.identity, self.control_dir = user, identity, control_dir

    def call(self, host: str, payload: dict) -> dict:
        try:
            ipaddress.ip_address(host.strip("[]"))
            ssh_host = f"[{host.strip('[]')}]" if ":" in host else host
        except ValueError:
            ssh_host = host
        argv = ["ssh", "-T", "-o", "ControlMaster=auto", "-o", "ControlPersist=90",
                "-o", f"ControlPath={self.control_dir}/%C", "-o", "BatchMode=no",
                "-o", "ConnectTimeout=15"]
        if self.identity:
            argv += ["-i", self.identity, "-o", "IdentitiesOnly=yes"]
        remote_command = "tunnelmgr-mesh-v1" if os.environ.get("TUNNELMGR_PROFILE") else "python3 -c " + shlex.quote(REMOTE)
        argv += [f"{self.user}@{ssh_host}", remote_command]
        proc = subprocess.run(argv, input=json.dumps(payload), text=True, capture_output=True)
        if proc.returncode:
            detail = proc.stderr.strip() or proc.stdout.strip() or f"ssh exited {proc.returncode}"
            raise RuntimeError(f"{host}: {detail}")
        try:
            result = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"{host}: invalid response from remote manager") from e
        if result.get("error"):
            raise RuntimeError(f"{host}: {result['error']}")
        return result

    def close(self, host: str) -> None:
        try:
            ipaddress.ip_address(host.strip("[]"))
            ssh_host = f"[{host.strip('[]')}]" if ":" in host else host
        except ValueError:
            ssh_host = host
        subprocess.run(["ssh", "-O", "exit", "-o", f"ControlPath={self.control_dir}/%C",
                        f"{self.user}@{ssh_host}"], text=True, capture_output=True, timeout=5)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--nodes", required=True, help="comma-separated node IDs")
    p.add_argument("--endpoints", required=True, help="node=SSH/public-host mappings")
    p.add_argument("--topology", choices=("full", "hub"), default="full")
    p.add_argument("--hub")
    p.add_argument("--direction", choices=("direct", "reverse"), default="direct")
    p.add_argument("--pool", default="10.240.0.0/16")
    p.add_argument("--ssh-user", default="root")
    p.add_argument("--identity", help="SSH private key path; otherwise SSH agent/password auth is used")
    p.add_argument("--check", action="store_true", help="check both endpoints and ping across every planned link")
    p.add_argument("--cleanup-legacy", action="store_true", help="remove unprefixed IDs left by the first preview deployer")
    p.add_argument("--yes", action="store_true", help="apply without the interactive confirmation")
    args = p.parse_args()
    try:
        nodes = [n.strip() for n in args.nodes.split(",") if n.strip()]
        endpoints = parse_mapping(args.endpoints, "endpoints")
        if set(nodes) - set(endpoints):
            raise ValueError("provide an SSH endpoint for every node")
        plan = mesh_plan(nodes, args.pool, args.topology, args.hub, args.direction,
                         endpoints=endpoints)
        plan["note"] = ("Check mode reads live status on both endpoints and sends two pings over each link."
                        if args.check else
                        "Apply mode installs both endpoints, generates a per-link secret, and rolls back on failure.")
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        if not args.check and not args.yes and input("\nDeploy these links now? [y/N] ").strip().lower() not in ("y", "yes"):
            return 1
        Path(args.identity).expanduser().resolve().stat() if args.identity else None
        ctl = tempfile.mkdtemp(prefix="tm-", dir="/tmp")
        try:
            Path(ctl).chmod(0o700)
            ssh = NodeSSH(args.ssh_user, str(Path(args.identity).expanduser()) if args.identity else None, ctl)
            done: list[tuple[str, str, str]] = []
            if args.cleanup_legacy:
                for link in plan["links"]:
                    legacy_id = link["id"]
                    secret_path = "/etc/backhaul/secrets/mesh-" + legacy_id + ".token"
                    for node in (link["listener"], link["initiator"]):
                        ssh.call(endpoints[node], {"op": "delete", "id": legacy_id,
                                                  "secret_file": secret_path})
                        print(f"REMOVED legacy instance {legacy_id} from {node}")
                return 0
            if args.check:
                failed = False
                for link in plan["links"]:
                    ident = "mesh-" + link["id"]
                    for node, peer_node in ((link["listener"], link["initiator"]),
                                            (link["initiator"], link["listener"])):
                        result = ssh.call(endpoints[node], {"op": "check", "id": ident})
                        print(f"{'OK' if result.get('ok') else 'FAIL'} {node} -> {peer_node} "
                              f"({result.get('peer', 'unknown')}): service="
                              f"{'active' if result.get('live', {}).get('active') else 'inactive'}, "
                              f"ping={'ok' if result.get('ping') else 'failed'}")
                        failed |= not result.get("ok", False)
                return 2 if failed else 0
            for link in plan["links"]:
                ident = "mesh-" + link["id"]
                secret_path = "/etc/backhaul/secrets/" + ident + ".token"
                secret = secrets.token_urlsafe(32)
                listener, initiator = link["listener"], link["initiator"]
                listener_cfg = dict(link["configs"][listener])
                listener_cfg["secret_file"] = secret_path
                listener_created = False
                try:
                    created = ssh.call(endpoints[listener], {"op": "create", "id": ident,
                        "config": listener_cfg, "secret": secret})
                    listener_created = True
                    actual_listener = created["config"]
                    client_cfg = dict(link["configs"][initiator])
                    client_cfg["secret_file"] = secret_path
                    host = endpoints[listener]
                    address = f"[{host}]" if ":" in host and not host.startswith("[") else host
                    client_cfg["peer"] = f"{address}:{actual_listener['listen'].rsplit(':',1)[1]}"
                    ssh.call(endpoints[initiator], {"op": "create", "id": ident,
                        "config": client_cfg, "secret": secret})
                    done.append((listener, initiator, ident))
                    print(f"DEPLOYED {link['node_a']} <-> {link['node_b']} ({ident}) "
                          f"{link['subnet']} listener={listener}:{actual_listener['listen']}")
                except Exception:
                    if listener_created:
                        try:
                            ssh.call(endpoints[listener], {"op": "delete", "id": ident,
                                       "secret_file": secret_path})
                        except Exception as cleanup:
                            print(f"ROLLBACK WARNING {listener}: {cleanup}", file=sys.stderr)
                    for old_listener, old_initiator, old_ident in reversed(done):
                        for node in (old_initiator, old_listener):
                            try:
                                ssh.call(endpoints[node], {"op": "delete", "id": old_ident,
                                           "secret_file": "/etc/backhaul/secrets/" + old_ident + ".token"})
                            except Exception as cleanup:
                                print(f"ROLLBACK WARNING {node}: {cleanup}", file=sys.stderr)
                    raise
            print(f"Mesh deployment complete: {len(done)} link(s).")
        finally:
            for host in set(endpoints.values()):
                try:
                    NodeSSH(args.ssh_user, str(Path(args.identity).expanduser()) if args.identity else None,
                            ctl).close(host)
                except Exception:
                    pass
            shutil.rmtree(ctl, ignore_errors=True)
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as e:
        print(f"mesh-deploy: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
