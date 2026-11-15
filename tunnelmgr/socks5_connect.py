#!/usr/bin/env python3
"""OpenSSH ProxyCommand bridge from a local Xray SOCKS5 listener."""
import ipaddress
import os
import selectors
import socket
import struct
import sys

def exact(sock,count):
    parts=[]
    while count:
        chunk=sock.recv(count)
        if not chunk:raise OSError('local Xray SOCKS connection closed')
        parts.append(chunk);count-=len(chunk)
    return b''.join(parts)

def socks_connect(port,host,destination_port):
    sock=socket.create_connection(('127.0.0.1',port),timeout=12)
    sock.settimeout(20)
    sock.sendall(b'\x05\x01\x00')
    if exact(sock,2)!=b'\x05\x00':raise OSError('Xray SOCKS listener rejected no-auth mode')
    try:
        address=ipaddress.ip_address(host.strip('[]'))
        atyp=1 if address.version==4 else 4
        encoded=bytes((atyp,))+address.packed
    except ValueError:
        encoded_host=host.rstrip('.').encode('idna')
        if not encoded_host or len(encoded_host)>255:raise ValueError('invalid SSH target hostname')
        encoded=b'\x03'+bytes((len(encoded_host),))+encoded_host
    sock.sendall(b'\x05\x01\x00'+encoded+struct.pack('!H',destination_port))
    version,status,reserved,atyp=exact(sock,4)
    if version!=5 or status!=0:raise OSError(f'Xray SOCKS connection failed (reply {status})')
    size={1:4,4:16}.get(atyp)
    if atyp==3:size=exact(sock,1)[0]
    if size is None:raise OSError('invalid SOCKS5 address type')
    exact(sock,size+2)
    return sock

def relay(sock):
    sock.setblocking(False)
    selector=selectors.DefaultSelector();selector.register(sock,selectors.EVENT_READ,'socket')
    try:selector.register(0,selectors.EVENT_READ,'stdin')
    except (OSError,ValueError):pass
    stdin_open=True
    while selector.get_map():
        for key,_ in selector.select():
            if key.data=='stdin':
                data=os.read(0,65536)
                if not data:
                    selector.unregister(0);stdin_open=False
                    try:sock.shutdown(socket.SHUT_WR)
                    except OSError:pass
                    continue
                sock.sendall(data)
            else:
                data=sock.recv(65536)
                if not data:return
                view=memoryview(data)
                while view:
                    sent=os.write(1,view);view=view[sent:]
    if not stdin_open:return

def main():
    if len(sys.argv)!=4:raise SystemExit('usage: socks5_connect.py SOCKS_PORT HOST PORT')
    port=int(sys.argv[1]);destination_port=int(sys.argv[3])
    if not 1<=port<=65535 or not 1<=destination_port<=65535:raise ValueError('port must be 1..65535')
    sock=socks_connect(port,sys.argv[2],destination_port)
    try:relay(sock)
    finally:sock.close()

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(f'avaTUN proxy line: {error}',file=sys.stderr)
        raise SystemExit(1)
