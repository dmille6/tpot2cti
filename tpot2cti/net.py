"""
Network helpers for tpot2cti.

Primarily provides :func:`wait_for_host`, a TCP-reachability poller used
to absorb the cold-start race when a dependent container (typically the
SSH tunnel to a T-Pot sensor) has not yet finished establishing its
listening socket. Per ``docs/LESSONS_LEARNED_FROM_V0.md`` §10 and the
V2_OPENSOURCE_HANDOFF cold-start race note: the importer can come up
before the tunnel's local forward is ready, and naive connect attempts
fail with ECONNREFUSED. Polling smooths that over.

No external dependencies — stdlib :mod:`socket` only.
"""

from __future__ import annotations

import logging
import socket
import time

__all__ = ["wait_for_host"]

logger = logging.getLogger(__name__)


def wait_for_host(
    host: str,
    port: int,
    timeout: int = 60,
    interval: float = 2.0,
) -> bool:
    """
    Poll ``host:port`` until it accepts a TCP connection or ``timeout``
    elapses.

    Used to absorb the cold-start race between the tpot2cti importer
    container and its SSH-tunnel sidecar: the tunnel needs a moment to
    establish before its local forward starts accepting connections.

    Args:
        host: Hostname or IP address to probe.
        port: TCP port to probe.
        timeout: Total seconds to keep retrying before giving up.
            Must be >= 0; 0 means a single attempt.
        interval: Seconds to sleep between attempts. Must be > 0.

    Returns:
        ``True`` if a TCP connection succeeded within ``timeout`` seconds,
        ``False`` if the deadline expired without a successful connect.

    Raises:
        ValueError: If ``port`` is not in the valid TCP range, ``timeout``
            is negative, or ``interval`` is non-positive.
    """
    if not 0 < port < 65536:
        raise ValueError(f"port out of range: {port!r}")
    if timeout < 0:
        raise ValueError(f"timeout must be non-negative: {timeout!r}")
    if interval <= 0:
        raise ValueError(f"interval must be positive: {interval!r}")

    deadline = time.monotonic() + timeout
    attempt = 0

    while True:
        attempt += 1
        if _try_connect(host, port, interval):
            logger.info(
                "wait_for_host: %s:%d reachable after %d attempt(s)",
                host,
                port,
                attempt,
            )
            return True

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.warning(
                "wait_for_host: gave up on %s:%d after %d attempt(s) / %ds",
                host,
                port,
                attempt,
                timeout,
            )
            return False

        logger.debug(
            "wait_for_host: %s:%d not ready (attempt %d), "
            "sleeping %.1fs (%.1fs remaining)",
            host,
            port,
            attempt,
            interval,
            remaining,
        )
        # Don't oversleep past the deadline.
        time.sleep(min(interval, remaining))


def _try_connect(host: str, port: int, conn_timeout: float) -> bool:
    """
    Attempt a single TCP connect to ``host:port``.

    Returns ``True`` on success, ``False`` on any socket-level failure
    (refused, timeout, DNS, unreachable). Never raises.
    """
    try:
        with socket.create_connection((host, port), timeout=conn_timeout):
            return True
    except OSError:
        return False


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    ok = wait_for_host("127.0.0.1", 22, timeout=5, interval=1.0)
    print(f"localhost:22 reachable within 5s: {ok}")
