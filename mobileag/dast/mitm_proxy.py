"""Bounded, authenticated HTTP capture proxy.

This is NOT a TLS interception engine. CONNECT is explicitly unsupported;
import controlled TLS captures from a dedicated interception tool instead.
HTTP framing is parsed by h11 rather than an ad-hoc line/body parser.
"""
from __future__ import annotations
import asyncio
import hmac
import os
import h11
from typing import Optional
from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor
from mobileag.security.network import scoped_request
from mobileag.security.privacy import redact


class AsyncMITMProxy:
    def __init__(self, host='127.0.0.1', port=8082, auditor: Optional[TrafficAuditor]=None):
        self.host, self.port = host, port
        self.auditor = auditor or TrafficAuditor()
        self.transactions = []
        self._server = None
        self._is_running = False
        self._clients = set()

    @property
    def is_running(self):
        return self._is_running

    def record_transaction(self, tx):
        # Capture is evidence storage, so do not retain raw credentials.
        tx.url = redact(tx.url)
        tx.request_headers = redact(tx.request_headers)
        tx.response_headers = redact(tx.response_headers)
        tx.request_body = redact(tx.request_body)
        tx.response_body = redact(tx.response_body)
        self.transactions.append(tx)
        del self.transactions[:-1000]

    def get_transactions(self):
        return list(self.transactions)

    def clear_transactions(self):
        self.transactions.clear()

    def audit_captured_traffic(self):
        return self.auditor.audit_transactions(self.transactions)

    async def start(self):
        if self._is_running:
            return
        if self.host not in {'127.0.0.1','::1','localhost'}:
            raise ValueError('Capture proxy must bind to loopback')
        if not os.getenv('MOBILEAG_PROXY_TOKEN'):
            raise ValueError('MOBILEAG_PROXY_TOKEN is required')
        self._server = await asyncio.start_server(self._handle_client,self.host,self.port,limit=65536)
        self._is_running = True

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for task in list(self._clients):
            task.cancel()
        if self._clients:
            await asyncio.gather(*self._clients,return_exceptions=True)
        self._is_running = False

    async def _handle_client(self, reader, writer):
        task=asyncio.current_task()
        if len(self._clients)>=16:
            writer.close()
            return
        self._clients.add(task)
        connection=h11.Connection(h11.SERVER,max_incomplete_event_size=65536)
        async def respond(status,body=b'',headers=None):
            headers=[(k,v) for k,v in (headers or {}).items() if k.lower() not in
                     {'transfer-encoding','content-length','connection','keep-alive','proxy-authenticate','trailer','upgrade'}]
            headers += [('Content-Length',str(len(body))),('Connection','close')]
            writer.write(connection.send(h11.Response(status_code=status,headers=headers)))
            if body: writer.write(connection.send(h11.Data(data=body)))
            writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()
        try:
            async with asyncio.timeout(15):
                request=None
                body=bytearray()
                while True:
                    event=connection.next_event()
                    if event is h11.NEED_DATA:
                        data=await reader.read(65536)
                        if not data: return
                        connection.receive_data(data)
                    elif isinstance(event,h11.Request):
                        request=event
                        headers={k.decode().lower():v.decode() for k,v in event.headers}
                        token=headers.get('proxy-authorization','').removeprefix('Bearer ')
                        if not token or not hmac.compare_digest(token,os.environ.get('MOBILEAG_PROXY_TOKEN','')):
                            await respond(407,b'Proxy authentication required');return
                        # Credentials are needed only for this local proxy check. Never
                        # forward or retain them in request evidence.
                        headers.pop('proxy-authorization', None)
                        if event.method == b'CONNECT':
                            await respond(501,b'TLS interception is not supported');return
                    elif isinstance(event,h11.Data):
                        body.extend(event.data)
                        if len(body)>1024*1024:
                            await respond(413);return
                    elif isinstance(event,h11.EndOfMessage):
                        break
                    else:
                        return
                if request is None: return
                method=request.method.decode('ascii');url=request.target.decode('ascii')
                try:
                    response=await scoped_request(url,method,headers,bytes(body),timeout=5,raw=True)
                except PermissionError:
                    await respond(403,b'Destination outside scope');return
                except Exception:
                    await respond(502,b'Upstream request failed');return
                self.record_transaction(HTTPTransaction(url=url,method=method,request_headers=headers,
                    request_body=bytes(body).decode('utf-8',errors='replace'),response_status=response['status_code'],
                    response_headers=response['headers'],response_body=response['body'].decode('utf-8',errors='replace')))
                await respond(response['status_code'],response['body'],response['headers'])
        except (TimeoutError,h11.ProtocolError,UnicodeError,ConnectionError):
            pass
        finally:
            writer.close()
            try: await writer.wait_closed()
            except ConnectionError: pass
            self._clients.discard(task)
