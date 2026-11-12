#!/bin/sh
# Three isolated routers; no interface or route is added to the host.
set -eu
src=$(cd "$(dirname "$0")/../tunnelmgr" && pwd)/network.py
prefix=tmcheck$$
clean(){ for i in a b c; do ip netns del "$prefix$i" 2>/dev/null || :; done; }
trap clean EXIT
for i in a b c; do ip netns add "$prefix$i"; ip -n "$prefix$i" link set lo up; done
pair(){
 ip -n "$prefix$1" link add "$3" type veth peer name "$4" netns "$prefix$2"
 ip -n "$prefix$1" addr add "$5/30" dev "$3"; ip -n "$prefix$2" addr add "$6/30" dev "$4"
 ip -n "$prefix$1" link set "$3" up; ip -n "$prefix$2" link set "$4" up
}
pair a b ab ba 192.0.2.1 192.0.2.2
pair b c bc cb 192.0.2.5 192.0.2.6
apply(){ ip netns exec "$prefix$1" python3 -c 'import sys,json,runpy;runpy.run_path(sys.argv[1])["apply"](json.loads(sys.argv[2]),sys.argv[3]=="up")' "$src" "$2" "${3:-up}"; }
tun(){ apply "$1" "{\"kind\":\"$kind\",\"interface\":\"$2\",\"inner_local\":\"$3/30\",\"inner_peer\":\"$4/30\",\"outer_local\":\"$5\",\"outer_peer\":\"$6\"}" "${7:-up}"; }
route(){ apply "$1" "{\"kind\":\"routes\",\"routes\":[{\"prefix\":\"$2\",\"via\":\"$3\",\"interface\":\"$4\"}]}" "${5:-up}"; }
for kind in gre ipip; do
 for action in up down; do
  if [ "$action" = down ]; then
    route a 10.249.0.4/30 10.249.0.2 t0 down; route c 10.249.0.0/30 10.249.0.5 t0 down
    for iface in "tb$$" "tc$$"; do apply b "{\"kind\":\"forward\",\"interface\":\"$iface\"}" down; done
  fi
  tun a t0 10.249.0.1 10.249.0.2 192.0.2.1 192.0.2.2 "$action"
  tun b "tb$$" 10.249.0.2 10.249.0.1 192.0.2.2 192.0.2.1 "$action"
  tun b "tc$$" 10.249.0.5 10.249.0.6 192.0.2.5 192.0.2.6 "$action"
  tun c t0 10.249.0.6 10.249.0.5 192.0.2.6 192.0.2.5 "$action"
  if [ "$action" = up ]; then
    for iface in "tb$$" "tc$$"; do apply b "{\"kind\":\"forward\",\"interface\":\"$iface\"}"; done
    route a 10.249.0.4/30 10.249.0.2 t0; route c 10.249.0.0/30 10.249.0.5 t0
    ip netns exec "${prefix}a" ping -q -c 2 -W 2 10.249.0.6
  fi
 done
done
