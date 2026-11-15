"""Parse supported Xray share links and build isolated managed client configs."""
import base64
import ipaddress
import json
import re
import urllib.parse

ID_RE=re.compile(r'^[a-z0-9][a-z0-9_-]{0,47}$')

def _first(query,*names,default=''):
    for name in names:
        values=query.get(name)
        if values and values[0] != '':return values[0]
    return default

def _number(value,label,minimum=1,maximum=65535):
    try:number=int(value)
    except (TypeError,ValueError) as error:raise ValueError(f'{label} must be a number') from error
    if not minimum<=number<=maximum:raise ValueError(f'{label} must be {minimum}..{maximum}')
    return number

def _decode_vmess(value):
    encoded=value.strip()
    encoded+='='*((-len(encoded))%4)
    try:data=json.loads(base64.urlsafe_b64decode(encoded.encode()).decode())
    except Exception as error:raise ValueError('VMess link does not contain valid base64 JSON') from error
    if not isinstance(data,dict):raise ValueError('VMess configuration must be a JSON object')
    return data

def _stream(network,security,query,*,vmess=None):
    vmess=vmess or {}
    network=(network or 'tcp').lower()
    methods={'raw':'raw','tcp':'raw','ws':'websocket','websocket':'websocket','grpc':'grpc',
             'httpupgrade':'httpupgrade','xhttp':'xhttp','kcp':'mkcp','mkcp':'mkcp','http':'raw'}
    if network not in methods:
        raise ValueError(f'Xray transport {network!r} is not supported by managed proxy lines')
    method=methods[network]
    result={'method':method,'security':security or 'none'}
    if result['security']=='reality' and method not in ('raw','xhttp','grpc'):
        raise ValueError('REALITY requires TCP/RAW, gRPC or XHTTP transport')
    if method=='raw':
        header=_first(query,'headerType',default=str(vmess.get('type','http' if network=='http' else 'none')))
        if header and header!='none':result['rawSettings']={'header':{'type':header}}
    elif method=='websocket':
        path=_first(query,'path',default=str(vmess.get('path','/')))
        host=_first(query,'host',default=str(vmess.get('host','')))
        result['wsSettings']={'path':path or '/'}
        if host:result['wsSettings']['headers']={'Host':host}
    elif method=='grpc':
        service=_first(query,'serviceName','service_name',default=str(vmess.get('path','')))
        authority=_first(query,'authority','host',default=str(vmess.get('host','')))
        result['grpcSettings']={'serviceName':service}
        if authority:result['grpcSettings']['authority']=authority
        mode=_first(query,'mode',default='')
        if mode:result['grpcSettings']['multiMode']=mode.lower() in ('multi','mult')
    elif method=='httpupgrade':
        settings={'path':_first(query,'path',default=str(vmess.get('path','/'))) or '/'}
        host=_first(query,'host',default=str(vmess.get('host','')))
        if host:settings['host']=host
        result['httpupgradeSettings']=settings
    elif method=='xhttp':
        settings={'path':_first(query,'path',default=str(vmess.get('path','/'))) or '/'}
        host=_first(query,'host',default=str(vmess.get('host','')))
        if host:settings['host']=host
        mode=_first(query,'mode',default='')
        if mode:settings['mode']=mode
        result['xhttpSettings']=settings
    elif method=='mkcp':
        settings={}
        header=_first(query,'headerType',default=str(vmess.get('type','none')))
        if header:settings['header']={'type':header}
        seed=_first(query,'seed',default=str(vmess.get('path','')))
        if seed:settings['seed']=seed
        result['kcpSettings']=settings
    if result['security']=='tls':
        tls={'serverName':_first(query,'sni','serverName',default=str(vmess.get('sni',''))),
             'allowInsecure':_first(query,'allowInsecure','insecure',default='0').lower() in ('1','true')}
        fingerprint=_first(query,'fp',default=str(vmess.get('fp','')))
        if fingerprint:tls['fingerprint']=fingerprint
        alpn=_first(query,'alpn',default=str(vmess.get('alpn','')))
        if alpn:tls['alpn']=[x for x in alpn.split(',') if x]
        result['tlsSettings']={k:v for k,v in tls.items() if v not in ('',None)}
    elif result['security']=='reality':
        reality={'serverName':_first(query,'sni','serverName',default=str(vmess.get('sni',''))),
                 'fingerprint':_first(query,'fp',default=str(vmess.get('fp','chrome'))),
                 'password':_first(query,'pbk','password','publicKey'),
                 'shortId':_first(query,'sid','shortId'),
                 'spiderX':_first(query,'spx','spiderX',default='/')}
        if not reality['serverName'] or not reality['password']:
            raise ValueError('Reality links require sni and pbk parameters')
        result['realitySettings']=reality
    elif result['security'] not in ('none',''):
        raise ValueError(f'Xray security mode {result["security"]!r} is not supported')
    return result

def parse_link(ident,link):
    if not isinstance(ident,str) or not ID_RE.fullmatch(ident):raise ValueError('invalid proxy line ID')
    if not isinstance(link,str) or not link.strip() or len(link)>16384:raise ValueError('paste one VLESS, VMess or Trojan share link')
    link=link.strip()
    if '\n' in link or '\r' in link:raise ValueError('paste one proxy link at a time')
    tag='line_'+ident
    if link.lower().startswith('vmess://'):
        data=_decode_vmess(link.split('://',1)[1].split('#',1)[0])
        address=_safe_host(str(data.get('add','')).strip());port=_number(data.get('port'), 'proxy port')
        user=str(data.get('id','')).strip()
        if not address or not user:raise ValueError('VMess link is missing its server or user ID')
        alter_id=_number(data.get('aid',0),'VMess alterId',0,65535)
        outbound={'tag':tag,'protocol':'vmess','settings':{'address':address,'port':port,
                  'id':user,'security':str(data.get('scy') or data.get('cipher') or 'auto'),
                  **({'alterId':alter_id} if alter_id else {})}}
        query={}
        for source,target in (('sni','sni'),('fp','fp'),('alpn','alpn'),('host','host'),('path','path'),('serviceName','serviceName')):
            if data.get(source):query[target]=[str(data[source])]
        security=str(data.get('tls','') or 'none').lower()
        if security in ('tls','reality'):
            for key in ('pbk','sid','spx'):
                if data.get(key):query[key]=[str(data[key])]
        stream=_stream(str(data.get('net','tcp')),security,query,vmess=data)
        label=str(data.get('ps') or address)
        protocol='vmess'
    else:
        try:parsed=urllib.parse.urlsplit(link)
        except ValueError as error:raise ValueError('invalid proxy share link') from error
        protocol=parsed.scheme.lower()
        if protocol not in ('vless','trojan'):raise ValueError('only VLESS, VMess and Trojan links are supported')
        if not parsed.hostname:raise ValueError('proxy link is missing its server address')
        address=_safe_host(parsed.hostname)
        port=_number(parsed.port,'proxy port')
        query=urllib.parse.parse_qs(parsed.query,keep_blank_values=True)
        network=_first(query,'type','network',default='tcp')
        security=_first(query,'security',default='none').lower()
        if protocol=='vless':
            user=urllib.parse.unquote(parsed.username or '')
            if not user:raise ValueError('VLESS link is missing its UUID/user ID')
            settings={'address':address,'port':port,'id':user,'encryption':_first(query,'encryption',default='none')}
            flow=_first(query,'flow')
            if flow:settings['flow']=flow
            outbound={'tag':tag,'protocol':'vless','settings':settings}
        else:
            password=urllib.parse.unquote(parsed.username or '')
            if not password:raise ValueError('Trojan link is missing its password')
            outbound={'tag':tag,'protocol':'trojan','settings':{'address':address,'port':port,'password':password}}
        stream=_stream(network,security,query)
        label=urllib.parse.unquote(parsed.fragment) or address
    outbound['streamSettings']=stream
    return {'id':ident,'tag':tag,'protocol':protocol,'address':address,'port':port,'label':label[:120],
            'outbound':outbound,'created_at':None}

def _safe_host(value):
    if not isinstance(value,str) or not value or len(value)>253 or any(c.isspace() for c in value):raise ValueError('destination host is invalid')
    if value.startswith('[') and value.endswith(']'):value=value[1:-1]
    try:return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?',value):raise ValueError('destination must be an IP address or DNS name')
        return value.rstrip('.').lower()

def build_config(lines,ssh_lines=(),forwards=()):
    """Create a fail-closed Xray config for exactly the supplied managed paths."""
    by_id={line['id']:line for line in lines}
    needed={str(x) for x in ssh_lines}
    for item in forwards:needed.add(item['line_id'])
    missing=needed-by_id.keys()
    if missing:raise ValueError('unknown proxy line(s): '+', '.join(sorted(missing)))
    config={'log':{'loglevel':'warning'},'inbounds':[],'outbounds':[{'tag':'blocked','protocol':'blackhole'}],
            'routing':{'domainStrategy':'AsIs','rules':[]}}
    for ident in sorted(needed):config['outbounds'].append(by_id[ident]['outbound'])
    for ident in sorted(set(map(str,ssh_lines))):
        port=by_id[ident]['socks_port']
        tag='ssh_'+ident
        config['inbounds'].append({'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False},'tag':tag})
        config['routing']['rules'].append({'type':'field','inboundTag':[tag],'outboundTag':by_id[ident]['tag']})
    seen=set()
    for item in forwards:
        ident=item['id'];line_id=item['line_id']
        if not ID_RE.fullmatch(ident):raise ValueError('invalid proxy forward ID')
        listen=_safe_host(item.get('listen_ip','0.0.0.0'))
        port=_number(item.get('listen_port'),'listen port')
        target=_safe_host(item.get('target_host',''))
        target_port=_number(item.get('target_port'),'destination port')
        network=item.get('network','tcp')
        if network not in ('tcp','udp'):raise ValueError('proxy forward protocol must be TCP or UDP')
        try:bind_ip=ipaddress.ip_address(listen)
        except ValueError:raise ValueError('listen address must be an IP address')
        key=(str(bind_ip),port,network)
        if key in seen:raise ValueError(f'duplicate {network.upper()} listener {listen}:{port}')
        seen.add(key)
        tag='fwd_'+ident
        config['inbounds'].append({'listen':listen,'port':port,'protocol':'tunnel','settings':{'allowedNetwork':network,'rewriteAddress':target,'rewritePort':target_port,'followRedirect':False},'tag':tag})
        config['routing']['rules'].append({'type':'field','inboundTag':[tag],'outboundTag':by_id[line_id]['tag']})
    return config
