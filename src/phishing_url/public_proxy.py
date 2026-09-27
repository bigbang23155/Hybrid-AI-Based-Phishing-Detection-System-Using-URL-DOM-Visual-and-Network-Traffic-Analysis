"""Bounded public-IP CONNECT/HTTP gateway for the isolated pilot browser."""
from __future__ import annotations
import argparse
import asyncio
import ipaddress
import json
import socket
from urllib.parse import urlsplit


def public_address(value):
    address=ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or address.is_unspecified:
        raise ValueError('non_public_destination')
    if getattr(address,'ipv4_mapped',None) is not None:
        public_address(str(address.ipv4_mapped))
    return str(address)


def destination(method,target):
    parts=urlsplit('https://'+target if method=='CONNECT' else target)
    if parts.scheme not in ('http','https') or not parts.hostname or parts.username is not None:
        raise ValueError('invalid_destination')
    port=parts.port or (443 if parts.scheme=='https' else 80)
    if port not in (80,443): raise ValueError('disallowed_port')
    if parts.hostname.lower() in ('localhost','metadata.google.internal'):
        raise ValueError('non_public_destination')
    return parts.hostname,port,parts


class Gateway:
    def __init__(self):
        self.total_bytes=0;self.connections=0;self.limit=200*1024*1024
        self.semaphore=asyncio.Semaphore(32)

    async def handle(self,reader,writer):
        remote=None
        try:
            async with self.semaphore:
                self.connections+=1
                if self.connections>1500 or self.total_bytes>=self.limit: raise ValueError('run_budget_exceeded')
                header=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5)
                if len(header)>16384: raise ValueError('header_too_large')
                method,target,version=header.split(b'\r\n',1)[0].decode('ascii').split()
                if method not in ('CONNECT','GET','HEAD','OPTIONS'): raise ValueError('method_blocked')
                host,port,parts=destination(method,target)
                infos=await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host,port,type=socket.SOCK_STREAM),5)
                addresses=sorted({public_address(i[4][0]) for i in infos})
                if not addresses: raise ValueError('dns_empty')
                # Connect to the validated numeric address, never resolve host again.
                ipv4=[x for x in addresses if ':' not in x]
                ip=(ipv4 or addresses)[0]
                upstream,remote=await asyncio.wait_for(asyncio.open_connection(ip,port),6)
                print(json.dumps({'event':'connected','host':host,'ip':ip,'port':port}),flush=True)
                if method=='CONNECT':
                    writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n');await writer.drain()
                else:
                    path=parts.path or '/'
                    if parts.query:path+='?'+parts.query
                    # Origin request with host derived from the checked destination.
                    retained=[line for line in header.split(b'\r\n')[1:] if line and
                              line.split(b':',1)[0].lower() not in (b'host',b'connection',b'proxy-connection',b'proxy-authorization')]
                    remote.write(f'{method} {path} HTTP/1.1\r\nHost: {parts.netloc}\r\nConnection: close\r\n'.encode()+b'\r\n'.join(retained)+b'\r\n\r\n')
                    await remote.drain()
                transferred=[0]
                async def pump(source,sink):
                    while True:
                        chunk=await source.read(65536)
                        if not chunk: return
                        transferred[0]+=len(chunk);self.total_bytes+=len(chunk)
                        if transferred[0]>10*1024*1024 or self.total_bytes>self.limit:raise ValueError('byte_budget_exceeded')
                        sink.write(chunk);await sink.drain()
                tasks=[asyncio.create_task(pump(reader,remote)),asyncio.create_task(pump(upstream,writer))]
                try:
                    done,pending=await asyncio.wait(tasks,timeout=35,return_when=asyncio.FIRST_COMPLETED)
                    for t in done:t.result()
                finally:
                    for t in tasks:t.cancel()
                    await asyncio.gather(*tasks,return_exceptions=True)
        except Exception as exc:
            print(json.dumps({'event':'blocked_or_failed','reason':type(exc).__name__+': '+str(exc)[:150]}),flush=True)
            try:writer.write(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');await writer.drain()
            except Exception:pass
        finally:
            if remote:remote.close()
            writer.close()


async def serve(port):
    gateway=Gateway()
    server=await asyncio.start_server(gateway.handle,'0.0.0.0',port,limit=16384)
    async with server:await server.serve_forever()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',type=int,default=8888)
    asyncio.run(serve(parser.parse_args().port))


if __name__=='__main__':main()
