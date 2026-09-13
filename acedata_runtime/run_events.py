from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import dataclass
from typing import Any


class CursorGap(ValueError):
    pass


@dataclass(frozen=True)
class EventFrame:
    event_id: int
    payload: dict[str, Any]
    size: int


class RunEventBuffer:
    def __init__(self, *, max_events: int = 4096, max_bytes: int = 8 * 1024 * 1024):
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.frames: deque[EventFrame] = deque()
        self.total_bytes = 0
        self.last_event_id = 0
        self.closed = False
        self.closed_at: float | None = None
        self._waiters: set[asyncio.Event] = set()

    @property
    def first_event_id(self) -> int:
        return self.frames[0].event_id if self.frames else self.last_event_id + 1

    def publish(self, payload: dict[str, Any], *, terminal: bool = False) -> int:
        if self.closed:
            return self.last_event_id
        self.last_event_id += 1
        size = len(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        )
        frame = EventFrame(self.last_event_id, payload, size)
        self.frames.append(frame)
        self.total_bytes += size
        while len(self.frames) > self.max_events or self.total_bytes > self.max_bytes:
            removed = self.frames.popleft()
            self.total_bytes -= removed.size
        if terminal:
            self.closed = True
            self.closed_at = time.time()
        for waiter in tuple(self._waiters):
            waiter.set()
        return frame.event_id

    def expire(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.closed_at = time.time()
        for waiter in tuple(self._waiters):
            waiter.set()

    def after(self, cursor: int) -> list[EventFrame]:
        if cursor < self.first_event_id - 1:
            raise CursorGap(
                f"event cursor {cursor} is before retained event {self.first_event_id}"
            )
        return [frame for frame in self.frames if frame.event_id > cursor]

    async def wait_after(
        self, cursor: int, timeout: float = 30.0
    ) -> tuple[list[EventFrame], bool]:
        frames = self.after(cursor)
        if frames or self.closed:
            return frames, self.closed
        waiter = asyncio.Event()
        self._waiters.add(waiter)
        try:
            frames = self.after(cursor)
            if frames or self.closed:
                return frames, self.closed
            await asyncio.wait_for(waiter.wait(), timeout=timeout)
            return self.after(cursor), self.closed
        finally:
            self._waiters.discard(waiter)
