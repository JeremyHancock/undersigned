"""At-least-once delivery of receipts and revocation events to a service.

Delivery is tried once inline, then retried with backoff by whoever calls
:meth:`Outbox.deliver_due` (a background task, a cron job). By default it never
gives up: an undelivered revocation is exactly the one that matters. Receivers
must be idempotent; the tokens carry a ``jti`` for that.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Callable

#: ``send(url, body, headers) -> HTTP status``. Raise ``OSError`` on transport failure.
Sender = Callable[[str, bytes, dict[str, str]], int]

BACKOFF_SECONDS = (5, 15, 45, 135, 300)


def http_post(url: str, body: bytes, headers: dict[str, str]) -> int:
    """Default sender: a plain HTTPS POST with a 10 second timeout."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


@dataclass
class Delivery:
    url: str
    media_type: str
    token: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: str = "queued"  # queued | delivered | failed
    attempts: int = 0
    next_attempt_at: float = 0.0
    last_error: str = ""


class Outbox:
    def __init__(
        self,
        send: Sender = http_post,
        *,
        clock: Callable[[], float] = time.time,
        backoff: tuple[int, ...] = BACKOFF_SECONDS,
        max_attempts: int | None = None,
    ):
        self._send = send
        self._clock = clock
        self._backoff = backoff
        self._max_attempts = max_attempts
        self.deliveries: list[Delivery] = []

    def enqueue(self, url: str, media_type: str, token: str) -> Delivery:
        """Queue a token and try to deliver it straight away."""
        delivery = Delivery(url=url, media_type=media_type, token=token)
        self.deliveries.append(delivery)
        self._attempt(delivery)
        return delivery

    def deliver_due(self) -> int:
        """Retry queued deliveries whose backoff has elapsed. Returns how many succeeded."""
        now = self._clock()
        delivered = 0
        for delivery in self.deliveries:
            if delivery.status == "queued" and delivery.next_attempt_at <= now:
                delivered += self._attempt(delivery)
        return delivered

    def forget_delivered(self) -> int:
        """Drop the records of completed deliveries. Returns how many were dropped."""
        kept = [d for d in self.deliveries if d.status != "delivered"]
        dropped = len(self.deliveries) - len(kept)
        self.deliveries = kept
        return dropped

    def pending(self) -> list[Delivery]:
        return [d for d in self.deliveries if d.status == "queued"]

    def _attempt(self, delivery: Delivery) -> bool:
        delivery.attempts += 1
        headers = {"Content-Type": delivery.media_type, "Accept": "application/json"}
        try:
            status = self._send(delivery.url, delivery.token.encode("ascii"), headers)
            error = "" if 200 <= status < 300 else f"HTTP {status}"
        except OSError as exc:
            error = f"transport error: {exc}"
        if not error:
            delivery.status, delivery.last_error = "delivered", ""
            return True
        delivery.last_error = error
        if self._max_attempts is not None and delivery.attempts >= self._max_attempts:
            delivery.status = "failed"
        else:
            wait = self._backoff[min(delivery.attempts - 1, len(self._backoff) - 1)]
            delivery.next_attempt_at = self._clock() + wait
        return False
