import asyncio

import pytest

from acedata_runtime.run_events import CursorGap, RunEventBuffer


def test_replays_independently_and_reports_gap():
    stream = RunEventBuffer(max_events=2, max_bytes=10_000)
    assert stream.publish({"event": "one"}) == 1
    assert stream.publish({"event": "two"}) == 2
    assert [frame.event_id for frame in stream.after(0)] == [1, 2]
    assert stream.publish({"event": "three"}, terminal=True) == 3
    assert [frame.event_id for frame in stream.after(1)] == [2, 3]
    with pytest.raises(CursorGap):
        stream.after(0)
    assert stream.closed
    assert stream.closed_at is not None


def test_terminal_publication_is_idempotent_and_ignores_late_writes():
    stream = RunEventBuffer()
    assert stream.publish({"event": "run.completed"}, terminal=True) == 1
    assert stream.publish({"event": "run.cancelled"}, terminal=True) == 1
    assert stream.publish({"event": "message.delta"}) == 1
    assert [frame.payload["event"] for frame in stream.frames] == ["run.completed"]


def test_waiter_receives_new_frame():
    async def scenario():
        stream = RunEventBuffer()
        waiter = asyncio.create_task(stream.wait_after(0, timeout=1))
        await asyncio.sleep(0)
        stream.publish({"event": "tool.started"})
        frames, closed = await waiter
        assert [frame.event_id for frame in frames] == [1]
        assert not closed

    asyncio.run(scenario())


def test_expire_wakes_waiter_and_closes_stream():
    async def scenario():
        stream = RunEventBuffer()
        waiting = asyncio.create_task(stream.wait_after(0, timeout=1.0))
        await asyncio.sleep(0)
        stream.expire()
        frames, closed = await waiting
        assert frames == []
        assert closed is True
        assert stream.closed_at is not None

    asyncio.run(scenario())
