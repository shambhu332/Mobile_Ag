"""Embedded Asynchronous MITM Interception Proxy for Mobile Application DAST.

Provides a lightweight, zero-external-dependency transparent proxy server
implemented with Python's standard `asyncio.start_server`.

Features:
1. Intercepts plain HTTP requests and responses, extracting request headers, parameters, and bodies.
2. Supports HTTPS tunneling via the HTTP CONNECT method.
3. Automatically records all HTTPTransactions into an in-memory buffer.
4. Directly integrates with `TrafficAuditor` to evaluate live network streams
   against OWASP API Security Top 10 guidelines (BOLA, PII exposure, cleartext leaks, HSTS, CORS).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urlparse

from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor
from mobileag.reporting.finding import Finding

logger = logging.getLogger(__name__)


class AsyncMITMProxy:
    """Asynchronous local MITM proxy server for mobile application network analysis."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8082,
        auditor: Optional[TrafficAuditor] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.auditor = auditor or TrafficAuditor()
        self.transactions: list[HTTPTransaction] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._is_running: bool = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def record_transaction(self, tx: HTTPTransaction) -> None:
        """Append an HTTP transaction to the proxy's recorded stream."""
        self.transactions.append(tx)

    def get_transactions(self) -> list[HTTPTransaction]:
        """Return all recorded HTTP transactions."""
        return list(self.transactions)

    def clear_transactions(self) -> None:
        """Clear the in-memory recorded transaction buffer."""
        self.transactions.clear()

    def audit_captured_traffic(self) -> list[Finding]:
        """Audit all recorded traffic streams and return detected vulnerability findings."""
        return self.auditor.audit_transactions(self.transactions)

    async def start(self) -> None:
        """Start the asynchronous MITM proxy server."""
        if self._is_running:
            return

        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
        )
        self._is_running = True
        logger.info("AsyncMITMProxy listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop the proxy server and close active listeners."""
        if not self._is_running or not self._server:
            return

        self._server.close()
        await self._server.wait_closed()
        self._is_running = False
        logger.info("AsyncMITMProxy stopped")

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Process incoming client connections, handling HTTP proxying or CONNECT tunneling."""
        try:
            request_line = await client_reader.readline()
            if not request_line:
                client_writer.close()
                await client_writer.wait_closed()
                return

            req_line_str = request_line.decode("utf-8", errors="ignore").strip()
            parts = req_line_str.split()
            if len(parts) < 2:
                client_writer.close()
                await client_writer.wait_closed()
                return

            method, target = parts[0].upper(), parts[1]

            # Read client request headers
            headers: dict[str, str] = {}
            while True:
                line = await client_reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
                h_line = line.decode("utf-8", errors="ignore").strip()
                if ":" in h_line:
                    k, v = h_line.split(":", 1)
                    headers[k.strip()] = v.strip()

            if method == "CONNECT":
                await self._handle_connect(target, headers, client_reader, client_writer)
            else:
                await self._handle_http(method, target, headers, client_reader, client_writer)

        except Exception as e:
            logger.debug("Error in proxy handler: %s", e)
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(
        self,
        target: str,
        headers: dict[str, str],
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Handle HTTPS CONNECT tunneling and record the connection transaction."""
        host, port_str = target.split(":", 1) if ":" in target else (target, "443")
        port = int(port_str) if port_str.isdigit() else 443

        tx = HTTPTransaction(
            url=f"https://{host}:{port}/",
            method="CONNECT",
            request_headers=headers,
            response_status=200,
            response_headers={"Proxy-Agent": "MobileAg-MITM"},
        )
        self.record_transaction(tx)

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0,
            )
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: MobileAg-MITM\r\n\r\n")
            await client_writer.drain()

            # Bidirectional pipe
            async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
                try:
                    while True:
                        data = await src.read(4096)
                        if not data:
                            break
                        dst.write(data)
                        await dst.drain()
                except Exception:
                    pass

            await asyncio.gather(
                forward(client_reader, remote_writer),
                forward(remote_reader, client_writer),
                return_exceptions=True,
            )
            remote_writer.close()
            await remote_writer.wait_closed()
        except Exception as e:
            logger.debug("Failed CONNECT tunnel to %s:%d: %s", host, port, e)
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
        finally:
            client_writer.close()
            await client_writer.wait_closed()

    async def _handle_http(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Handle cleartext HTTP proxying, inspect payload, and record HTTPTransaction."""
        parsed = urlparse(target if target.startswith("http") else f"http://{target}")
        host = parsed.hostname or headers.get("Host", "127.0.0.1")
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # Read request body if Content-Length specified
        content_len = int(headers.get("Content-Length", 0))
        req_body = ""
        if content_len > 0 and content_len < 1_000_000:
            raw_body = await client_reader.read(content_len)
            req_body = raw_body.decode("utf-8", errors="ignore")

        tx = HTTPTransaction(
            url=target if target.startswith("http") else f"http://{host}:{port}{path}",
            method=method,
            request_headers=headers,
            request_body=req_body,
        )

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0,
            )

            # Reconstruct and send request
            fwd_req = f"{method} {path} HTTP/1.1\r\n"
            for hk, hv in headers.items():
                if hk.lower() not in ("proxy-connection", "connection"):
                    fwd_req += f"{hk}: {hv}\r\n"
            fwd_req += "Connection: close\r\n\r\n"
            remote_writer.write(fwd_req.encode("utf-8"))
            if req_body:
                remote_writer.write(req_body.encode("utf-8"))
            await remote_writer.drain()

            # Read response
            resp_data = await remote_reader.read()
            remote_writer.close()
            await remote_writer.wait_closed()

            # Parse status line and response
            if resp_data:
                header_end = resp_data.find(b"\r\n\r\n")
                if header_end != -1:
                    header_bytes = resp_data[:header_end]
                    body_bytes = resp_data[header_end + 4:]
                    resp_lines = header_bytes.decode("utf-8", errors="ignore").splitlines()
                    if resp_lines:
                        status_parts = resp_lines[0].split()
                        if len(status_parts) >= 2 and status_parts[1].isdigit():
                            tx.response_status = int(status_parts[1])
                    for r_line in resp_lines[1:]:
                        if ":" in r_line:
                            rk, rv = r_line.split(":", 1)
                            tx.response_headers[rk.strip()] = rv.strip()
                    tx.response_body = body_bytes.decode("utf-8", errors="ignore")[:10000]

            self.record_transaction(tx)
            client_writer.write(resp_data)
            await client_writer.drain()
        except Exception as e:
            logger.debug("Failed forwarding HTTP request to %s: %s", target, e)
            self.record_transaction(tx)
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
        finally:
            client_writer.close()
            await client_writer.wait_closed()
