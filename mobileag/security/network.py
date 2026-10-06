"""Explicit-origin network scope with DNS pinning, TLS verification and byte bounds."""
import asyncio
import ipaddress
import os
import socket
from urllib.parse import urlsplit
import httpx

MAX_RESPONSE = 1024 * 1024


async def _scoped_request(url, method='GET', headers=None, body=None, timeout=4.0, raw=False, allowed_origins=None, allow_private=None, loopback_only=False):
    parsed = urlsplit(url)
    if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Only HTTP(S) URLs without userinfo are supported')
    origin = f'{parsed.scheme}://{parsed.netloc}'
    # Explicit origins are supplied only by trusted server-side brokers, never
    # from user request bodies; default target scope remains unchanged.
    allowed = set(allowed_origins) if allowed_origins is not None else {s.strip().rstrip('/') for s in os.getenv('MOBILEAG_ALLOWED_ORIGINS','').split(',') if s.strip()}
    if origin not in allowed:
        raise PermissionError('Destination origin is outside configured test scope')
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(parsed.hostname,port,type=socket.SOCK_STREAM), 3)
    addresses = {info[4][0] for info in infos}
    allow_private = os.getenv('MOBILEAG_ALLOW_PRIVATE_TARGETS') == '1' if allow_private is None else allow_private
    if loopback_only and any(not ipaddress.ip_address(a).is_loopback for a in addresses):
        raise PermissionError('Local model address must resolve only to loopback')
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses) and not allow_private:
        raise PermissionError('Private/local destinations require explicit opt-in')
    address = sorted(addresses)[0]
    # Connect to the validated address, retaining the original Host and TLS server name.
    pinned = httpx.URL(url).copy_with(host=address)
    clean_headers = {k:v for k,v in (headers or {}).items() if k.lower() not in {'host','connection','proxy-authorization','content-length','transfer-encoding'}}
    clean_headers['Host'] = parsed.netloc
    clean_headers['Accept-Encoding'] = 'identity'
    async with httpx.AsyncClient(verify=True, trust_env=False, follow_redirects=False, timeout=min(max(timeout,0.1),15)) as client:
        async with client.stream(method, pinned, headers=clean_headers, content=body,
                extensions={'sni_hostname':parsed.hostname}) as response:
            chunks = bytearray()
            async for chunk in response.aiter_raw():
                if len(chunks) + len(chunk) > MAX_RESPONSE:
                    raise ValueError('Response size limit exceeded')
                chunks.extend(chunk)
            return {'status_code':response.status_code, 'headers':dict(response.headers), 'body': bytes(chunks) if raw else bytes(chunks).decode('utf-8',errors='replace')[:4096]}


async def scoped_request(*args, **kwargs):
    async with asyncio.timeout(20):
        return await _scoped_request(*args, **kwargs)
