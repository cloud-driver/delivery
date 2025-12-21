"""A small, in-memory Server-Sent Events (SSE) pub/sub helper.

Notes:
- This implementation is suitable for local development and single-process
  servers only. For production use with multiple workers or servers, use
  Redis pub/sub or another message broker.
"""

import json
import queue
import threading
from typing import Dict, Generator, List, Optional

_subscribers: Dict[str, List[queue.Queue]] = {}
_lock = threading.Lock()

KEEP_ALIVE_INTERVAL = 15  # seconds; how often to send a keep-alive comment


def _format_sse(payload: dict, event: Optional[str] = None) -> str:
    """Format a Python dict as SSE text block.

    The resulting string follows the SSE format: optional `event:` line
    followed by one or more `data:` lines and a blank line.
    """
    text = json.dumps(payload, ensure_ascii=False)
    parts: List[str] = []
    if event:
        parts.append(f"event: {event}")
    for line in text.splitlines():
        parts.append(f"data: {line}")
    parts.append("")
    return "\n".join(parts)


def subscribe(restaurant_id: str) -> Generator[str, None, None]:
    """Return a generator that yields SSE-formatted strings for a channel.

    Each subscriber gets its own queue. The generator yields keep-alive
    comments periodically if no events are available.
    """
    q: queue.Queue = queue.Queue()
    key = str(restaurant_id)
    with _lock:
        _subscribers.setdefault(key, []).append(q)

    try:
        # initial connected message
        yield _format_sse({"type": "connected", "restaurant_id": restaurant_id})
        while True:
            try:
                msg = q.get(timeout=KEEP_ALIVE_INTERVAL)
                yield _format_sse(msg.get("data", {}), event=msg.get("event"))
            except queue.Empty:
                # SSE keep-alive (comment line) to prevent proxies from closing
                yield ": keep-alive\n\n"
    finally:
        with _lock:
            lst = _subscribers.get(key, [])
            if q in lst:
                lst.remove(q)


def publish(restaurant_id: str, data: dict, event: Optional[str] = None) -> None:
    """Publish an event to all subscribers of a restaurant channel."""
    key = str(restaurant_id)
    with _lock:
        targets = list(_subscribers.get(key, []))
    payload = {"event": event, "data": data}
    for q in targets:
        try:
            q.put_nowait(payload)
        except Exception:
            # best-effort: ignore full queues or other issues
            continue


def broadcast_all(data: dict, event: Optional[str] = None) -> None:
    """Send an event to every subscriber across all channels."""
    with _lock:
        all_queues = [q for queues in _subscribers.values() for q in queues]
    payload = {"event": event, "data": data}
    for q in all_queues:
        try:
            q.put_nowait(payload)
        except Exception:
            continue
