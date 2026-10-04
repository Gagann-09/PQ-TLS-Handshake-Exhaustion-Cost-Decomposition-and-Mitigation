"""
D2 Userspace Admission Proxy
Listens on 0.0.0.0:4433, forwards accepted connections to 127.0.0.1:4434
Implements per-source-IP token bucket rate limiting (5 tokens/sec, capacity 5)
"""

import asyncio
import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
)
logger = logging.getLogger("admission_proxy")

# Configuration
PROXY_LISTEN_HOST = "0.0.0.0"
PROXY_LISTEN_PORT = 4433
TARGET_HOST = "tls-server"
TARGET_PORT = 4434

# Token bucket parameters (D7-003)
CAPACITY = 5          # Initial burst allowance
REFILL_RATE = 5.0     # Tokens per second
INITIAL_TOKENS = 5    # Start with full capacity
IDLE_CLEANUP_SECONDS = 60  # Remove buckets inactive this long


@dataclass
class TokenBucket:
    """Token bucket for per-source rate limiting."""
    capacity: float = CAPACITY
    refill_rate: float = REFILL_RATE
    tokens: float = INITIAL_TOKENS
    last_refill: float = field(default_factory=time.monotonic)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def consume(self) -> bool:
        """Try to consume one token. Returns True if accepted, False if rejected."""
        self._refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class AdmissionProxy:
    """Asyncio TCP proxy with per-source token bucket admission control."""

    def __init__(self):
        self.buckets: Dict[str, TokenBucket] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

    def _get_client_ip(self, transport: asyncio.Transport) -> str:
        """Extract client IP from transport."""
        peername = transport.get_extra_info('peername')
        if peername:
            return peername[0]
        return "unknown"

    def _get_bucket(self, ip: str) -> TokenBucket:
        """Get or create token bucket for IP."""
        if ip not in self.buckets:
            self.buckets[ip] = TokenBucket()
            logger.debug("Created new token bucket for %s", ip)
        return self.buckets[ip]

    async def _cleanup_idle_buckets(self) -> None:
        """Periodically remove idle token buckets."""
        while True:
            await asyncio.sleep(IDLE_CLEANUP_SECONDS)
            now = time.monotonic()
            to_remove = [
                ip for ip, bucket in self.buckets.items()
                if now - bucket.last_refill > IDLE_CLEANUP_SECONDS
            ]
            for ip in to_remove:
                del self.buckets[ip]
                logger.debug("Removed idle bucket for %s", ip)

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Pipe data between reader and writer until EOF."""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_connection(self, client_reader: asyncio.StreamReader,
                                  client_writer: asyncio.StreamWriter) -> None:
        """Handle incoming connection: admission check + forward to TLS server."""
        client_ip = self._get_client_ip(client_writer.transport)
        bucket = self._get_bucket(client_ip)

        # Admission decision
        if not bucket.consume():
            logger.info("Admission REJECTED for %s (bucket empty: %.2f tokens)",
                       client_ip, bucket.tokens)
            client_writer.close()
            await client_writer.wait_closed()
            return

        logger.debug("Admission ACCEPTED for %s (%.2f tokens remaining)",
                    client_ip, bucket.tokens)

        # Connect to TLS server
        try:
            server_reader, server_writer = await asyncio.open_connection(
                TARGET_HOST, TARGET_PORT
            )
        except Exception as e:
            logger.error("Failed to connect to TLS server: %s", e)
            client_writer.close()
            await client_writer.wait_closed()
            return

        # Bidirectional piping
        await asyncio.gather(
            self._pipe(client_reader, server_writer),
            self._pipe(server_reader, client_writer),
            return_exceptions=True
        )

    async def start(self) -> None:
        """Start the proxy server."""
        self._cleanup_task = asyncio.create_task(self._cleanup_idle_buckets())

        server = await asyncio.start_server(
            self._handle_connection,
            PROXY_LISTEN_HOST,
            PROXY_LISTEN_PORT,
            reuse_address=True,
            reuse_port=True
        )

        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info("Admission proxy listening on %s -> %s:%d",
                   addrs, TARGET_HOST, TARGET_PORT)

        async with server:
            await server.serve_forever()

    async def stop(self) -> None:
        """Stop the proxy."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass


async def main() -> None:
    proxy = AdmissionProxy()
    try:
        await proxy.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())