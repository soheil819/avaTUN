"""Controller transaction: validate both ends, remove both, then recreate both."""
import json
import os
import secrets
import ipaddress
import tempfile


def startup_order(configs):
    def order(sid):
        cfg=configs[sid]
        return (cfg.get('role',cfg.get('mode'))=='client',sid)
    return sorted(configs,key=order)


def rebuild(t, ident, server_ids, configs=None, operation='restart'):
    if not isinstance(ident,str) or not t.ID.fullmatch(ident):raise ValueError('invalid tunnel id')
    if operation not in ('restart','update'):raise ValueError('invalid rebuild operation')
    if not isinstance(server_ids,list) or any(not isinstance(sid,str) for sid in server_ids) or len(server_ids)!=2 or len(set(server_ids))!=2:
        raise ValueError('Exactly two different managed tunnel endpoints are required.')
    servers={s['id']:s for s in t.server_rows()}
    if any(not isinstance(sid,str) or (sid!='local' and sid not in servers) for sid in server_ids):
        raise ValueError('Both tunnel endpoints must be managed servers.')
    if operation=='update' and (not isinstance(configs,dict) or set(configs)!=set(server_ids)):
        raise ValueError('Updated configurations for both tunnel endpoints are required.')
    def call(sid,op,config=None):
        if sid=='local':
            if op=='config':return t.tunnel_config(ident)
            if op=='validate':return t.validate_tunnel_config(config)
            if op=='delete':return t.remove_tunnel_endpoint(ident)
            return t.create_instance(config) if config['transport']=='backhaul' else t.create_native(config)
        payload={'op':op,'id':ident}
        if config is not None:payload['data']=config
        if op=='delete':payload={'op':'operate','id':ident,'action':'delete'}
        result=t.server_remote(servers[sid],payload)
        if isinstance(result,dict) and result.get('ok') is False:
            raise RuntimeError(result.get('error') or result.get('output') or op+' failed')
        return result
    with t.NATIVE_PAIR_LOCK:
        # Read and validate *all* endpoints before the first destructive call.
        previous={sid:call(sid,'config') for sid in server_ids}
        desired={sid:t.normalize_rebuild_config(ident,(configs or previous)[sid],previous[sid]) for sid in server_ids}
        a,b=[desired[sid] for sid in server_ids]
        if a['transport']!=b['transport']:raise ValueError('Both tunnel endpoints must use the same transport')
        if a['transport'] in ('backhaul','openvpn','ipsec-ikev2','ipsec-esp-udp'):
            roles={cfg.get('role',cfg.get('mode')) for cfg in (a,b)}
            if roles!={'client','server'}:raise ValueError('The tunnel needs one responder and one initiator')
        for left,right in (('inner_local','inner_peer'),('tun_local','tun_remote'),('local_ip','peer_ip')):
            if all(cfg.get(key) for cfg in (a,b) for key in (left,right)):
                if ipaddress.ip_interface(a[left]).ip!=ipaddress.ip_interface(b[right]).ip or ipaddress.ip_interface(a[right]).ip!=ipaddress.ip_interface(b[left]).ip:
                    raise ValueError('Local and peer addresses must be inverse on the two endpoints')
        for key in ('psk','preshared_key'):
            if a.get(key) and b.get(key) and a[key]!=b[key]:raise ValueError('The peers must use the same shared key')
        for sid in server_ids:call(sid,'validate',desired[sid])
        journal_dir=t.BASE/'rebuild-journals';journal_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
        journal=journal_dir/(ident+'-'+secrets.token_hex(8)+'.json')
        state={'id':ident,'operation':operation,'servers':server_ids,'previous':previous,'desired':desired,'phase':'prepared'}
        def checkpoint(phase):
            state['phase']=phase
            with tempfile.NamedTemporaryFile('w',dir=journal_dir,delete=False) as f:
                pending=f.name
                try:
                    json.dump(state,f);f.flush();os.fsync(f.fileno())
                    os.replace(pending,journal)
                finally:
                    if os.path.exists(pending):os.unlink(pending)
        checkpoint('prepared')
        touched=[];created=[]
        try:
            for sid in server_ids:
                touched.append(sid)
                checkpoint('removing:'+sid)
                call(sid,'delete')
            checkpoint('both_removed')
            for sid in startup_order(desired):
                checkpoint('creating:'+sid)
                call(sid,'create',desired[sid]);created.append(sid)
            checkpoint('complete')
        except Exception as error:
            # Clean attempted new endpoints before restoring saved configs. Never
            # delete shared secrets: the original credentials are reused.
            rollback_errors=[];ready=[]
            for sid in touched:
                try:
                    current=(t.find(ident) if sid=='local' else
                             next((x for x in t.server_remote(servers[sid],{'op':'list'}).get('items',[]) if x.get('id')==ident),None))
                    if current:call(sid,'delete')
                    ready.append(sid)
                except Exception as rollback:rollback_errors.append(sid+': '+str(rollback))
            for sid in startup_order(previous):
                if sid not in ready:continue
                try:call(sid,'create',t.normalize_rebuild_config(ident,previous[sid],previous[sid]))
                except Exception as rollback:rollback_errors.append(sid+': '+str(rollback))
            if rollback_errors:
                state['rollback_errors']=rollback_errors;checkpoint('rollback_incomplete')
                suffix='بازگردانی ناقص بود: '+' | '.join(rollback_errors)+'. نسخهٔ پشتیبان: '+str(journal)
            else:
                journal.unlink(missing_ok=True)
                suffix='تنظیمات قبلی هر دو سمت بازگردانده شد.'
            raise RuntimeError('بازسازی تونل ناموفق بود: '+str(error)+' · '+suffix) from error
        journal.unlink(missing_ok=True)
        return {'ok':True,'id':ident,'operation':operation,'servers':server_ids,
                'lifecycle':'remove-both-then-create','startup_order':startup_order(desired)}
