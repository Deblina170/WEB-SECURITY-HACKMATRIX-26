"""
Network Utilities (network_utils.py)
Non-blocking DNS and connectivity helper to prevent Windows DNS resolution hangs.
"""
import socket
import concurrent.futures
from typing import Optional

_DNS_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4)

def fast_dns_lookup(host: str, timeout: float = 0.3) -> Optional[str]:
    """
    Attempts to resolve hostname with a strict non-blocking timeout.
    Returns resolved IP or None if offline/unreachable/timeout.
    """
    try:
        future = _DNS_POOL.submit(socket.gethostbyname, host)
        return future.result(timeout=timeout)
    except Exception:
        return None
