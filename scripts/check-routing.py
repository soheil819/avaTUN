#!/usr/bin/env python3
"""Validate tunnel-scoped FRR configuration and BGP/OSPF policy commands."""
import pathlib
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tunnelmgr'))
import routing
import profiles

base={'kind':'routing','id':'office-link','protocol':'bgp','interface':'gre0','local_ip':'10.10.0.1','peer_ip':'10.10.0.2','router_id':'198.51.100.1','peer_router_id':'198.51.100.2','local_asn':65001,'peer_asn':65002,'networks':['10.20.0.0/24'],'peer_networks':['10.30.0.0/24']}
profiles.validate('network',base)
bgp='\n'.join(routing.commands(base,True))
assert 'neighbor 10.10.0.2 remote-as 65002' in bgp
assert 'neighbor 10.10.0.2 prefix-list TM' in bgp
assert 'network 10.20.0.0/24' in bgp
assert 'permit 10.30.0.0/24' in bgp
down='\n'.join(routing.commands(base,False))
assert 'no neighbor 10.10.0.2' in down and 'no network 10.20.0.0/24' in down
ospf={**base,'protocol':'ospf','area':'0.0.0.0'}
profiles.validate('network',ospf)
commands='\n'.join(routing.commands(ospf,True))
assert 'ip ospf area 0.0.0.0' in commands and 'ip ospf network point-to-point' in commands
assert 'redistribute connected route-map' in commands and 'permit 10.20.0.0/24' in commands
assert 'permit 10.30.0.0/24' in commands and 'distribute-list prefix-list' in commands
for bad in ({**base,'local_asn':0},{**base,'interface':'bad-iface-name-too-long'},{**base,'networks':['0.0.0.0/0']}):
    try:routing.validate(bad)
    except ValueError:pass
    else:raise AssertionError('unsafe or invalid routing config was accepted')
with tempfile.TemporaryDirectory(prefix='tm-frr-test-') as tmp, patch.object(routing,'RUN_DIR',pathlib.Path(tmp)), patch.object(routing.shutil,'which',return_value='/usr/bin/vtysh'),patch.object(routing.subprocess,'run') as run:
    run.return_value.returncode=0;run.return_value.stdout='';run.return_value.stderr=''
    result=routing.apply(base,True)
    assert result['ok'] and run.call_count==2
    assert run.call_args.args[0][0]=='/usr/bin/vtysh'
print('BGP/OSPF adjacency policy, exact prefix filters and unsafe-prefix rejection: PASS')
