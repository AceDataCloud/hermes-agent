from __future__ import annotations

import asyncio
import inspect
import tempfile
from unittest.mock import patch

from acedata_runtime.observations import project_tool_start
from acedata_runtime.run_events import RunEventBuffer
from agent.display import _detect_tool_failure
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from gateway.platforms.api_server import APIServerAdapter


def _adapter() -> APIServerAdapter:
    adapter = APIServerAdapter.__new__(APIServerAdapter)
    adapter._run_streams = {}
    adapter._run_streams_created = {}
    adapter._run_stream_subscribers = {}
    adapter._run_statuses = {}
    adapter._run_approval_sessions = {}
    adapter._active_run_agents = {}
    adapter._active_run_tasks = {}
    adapter._stopping_run_ids = set()
    adapter._run_idempotency_ids = set()
    adapter._run_owners = {}
    adapter._request_owns_run = lambda _request, _run_id: True
    return adapter


async def _test_http_replay() -> None:
    adapter = _adapter()
    adapter._check_auth = lambda _request: None

    replay = RunEventBuffer()
    replay.publish({"event": "one"})
    replay.publish({"event": "two"})
    replay.publish({"event": "run.completed"}, terminal=True)
    adapter._run_streams["run_replay"] = replay
    adapter._run_statuses["run_replay"] = {
        "object": "hermes.run",
        "run_id": "run_replay",
        "status": "completed",
        "event_contract": dict(adapter._RUN_EVENT_CONTRACT),
        "last_event_id": 3,
        "event_stream_complete": True,
    }

    gap = RunEventBuffer(max_events=2)
    gap.publish({"event": "one"})
    gap.publish({"event": "two"})
    gap.publish({"event": "run.completed"}, terminal=True)
    adapter._run_streams["run_gap"] = gap

    app = web.Application()
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    app.router.add_get("/v1/runs/{run_id}/events", adapter._handle_run_events)
    async with TestClient(TestServer(app)) as client:
        status = await client.get("/v1/runs/run_replay")
        assert status.status == 200
        assert (await status.json())["event_contract"] == adapter._RUN_EVENT_CONTRACT

        for _ in range(2):
            response = await client.get(
                "/v1/runs/run_replay/events",
                headers={"Last-Event-ID": "1"},
            )
            assert response.status == 200
            body = await response.text()
            assert "id: 1\n" not in body
            assert body.count("id: 2\n") == 1
            assert body.count("id: 3\n") == 1
            assert adapter._run_stream_subscribers == {}

        live = RunEventBuffer()
        adapter._run_streams["run_live"] = live
        first = await client.get("/v1/runs/run_live/events")
        second = await client.get("/v1/runs/run_live/events")
        assert adapter._run_stream_subscribers == {"run_live": 2}
        live.publish({"event": "run.completed"}, terminal=True)
        first_body, second_body = await asyncio.gather(first.text(), second.text())
        assert "id: 1\n" in first_body and "id: 1\n" in second_body
        for _ in range(20):
            if not adapter._run_stream_subscribers:
                break
            await asyncio.sleep(0.01)
        assert adapter._run_stream_subscribers == {}

        invalid = await client.get(
            "/v1/runs/run_replay/events",
            headers={"Last-Event-ID": "invalid"},
        )
        assert invalid.status == 400
        assert (await invalid.json())["error"]["code"] == "invalid_event_cursor"

        response = await client.get(
            "/v1/runs/run_gap/events",
            headers={"Last-Event-ID": "0"},
        )
        assert response.status == 409
        payload = await response.json()
        assert payload["error"]["code"] == "event_cursor_gap"
        assert payload["partial"] is True
        assert payload["first_event_id"] == 2
        assert payload["last_event_id"] == 3

        adapter._run_statuses["run_expired"] = {
            "object": "hermes.run",
            "run_id": "run_expired",
            "status": "completed",
            "event_contract": dict(adapter._RUN_EVENT_CONTRACT),
            "last_event_id": 7,
            "event_stream_complete": True,
        }
        expired = await client.get(
            "/v1/runs/run_expired/events",
            headers={"Last-Event-ID": "3"},
        )
        assert expired.status == 409
        expired_payload = await expired.json()
        assert expired_payload["error"]["code"] == "event_cursor_gap"
        assert expired_payload["partial"] is True
        assert expired_payload["first_event_id"] == 8
        assert expired_payload["last_event_id"] == 7

        hard_cap = RunEventBuffer()
        adapter._run_streams["run_hard_cap"] = hard_cap
        adapter._run_streams_created["run_hard_cap"] = 100.0
        adapter._set_run_status("run_hard_cap", "running", created_at=100.0)
        hanging = await client.get("/v1/runs/run_hard_cap/events")
        assert adapter._run_stream_subscribers == {"run_hard_cap": 1}
        adapter._sweep_orphaned_runs_once(100.0 + adapter._RUN_ACTIVE_STREAM_TTL + 1)
        assert "run_hard_cap" not in adapter._run_streams
        hard_cap_body = await hanging.text()
        assert ": stream closed\n\n" in hard_cap_body
        for _ in range(20):
            if not adapter._run_stream_subscribers:
                break
            await asyncio.sleep(0.01)
        assert adapter._run_stream_subscribers == {}


def main() -> None:
    asyncio.run(_test_http_replay())

    source = inspect.getsource(APIServerAdapter._handle_runs)
    assert "event = dict(approval_data or {})" not in source
    assert "_redact_approval_command" not in source

    adapter = _adapter()
    stream = RunEventBuffer()
    adapter._run_streams["run_test"] = stream
    adapter._run_streams_created["run_test"] = 100.0
    adapter._run_approval_sessions["run_test"] = "run_test"
    adapter._set_run_status("run_test", "queued", created_at=100.0)

    assert adapter._publish_run_event("run_test", {"event": "approval.responded"}) == 1
    assert (
        adapter._publish_run_event(
            "run_test",
            {
                "event": "run.completed",
                "output": "artifact ready",
                "usage": {"total_tokens": 7},
            },
        )
        == 2
    )
    status = dict(adapter._run_statuses["run_test"])
    assert status == {
        "object": "hermes.run",
        "run_id": "run_test",
        "status": "completed",
        "created_at": 100.0,
        "event_contract": {
            "version": 2,
            "replay": True,
            "public_observation_version": 1,
        },
        "last_event_id": 2,
        "event_stream_complete": True,
        "last_event": "run.completed",
        "output": "artifact ready",
        "usage": {"total_tokens": 7},
        "updated_at": status["updated_at"],
    }
    assert adapter._publish_run_event("run_test", {"event": "run.cancelled"}) == 2
    assert (
        adapter._publish_run_event(
            "run_test", {"event": "message.delta", "delta": "late"}
        )
        is None
    )
    adapter._set_run_status("run_test", "failed", error="late private error")
    assert adapter._run_statuses["run_test"] == status
    assert [frame.payload["event"] for frame in stream.frames] == [
        "approval.responded",
        "run.completed",
    ]

    closed_at = stream.closed_at
    assert closed_at is not None
    adapter._sweep_orphaned_runs_once(closed_at + adapter._RUN_STREAM_TTL + 1)
    assert "run_test" not in adapter._run_streams
    assert "run_test" in adapter._run_statuses
    adapter._sweep_orphaned_runs_once(
        status["updated_at"] + adapter._RUN_STATUS_TTL + 1
    )
    assert "run_test" not in adapter._run_statuses

    active = RunEventBuffer()
    adapter._run_streams["run_active"] = active
    adapter._run_streams_created["run_active"] = 200.0
    adapter._set_run_status("run_active", "running", created_at=200.0)
    adapter._sweep_orphaned_runs_once(200.0 + adapter._RUN_ACTIVE_STREAM_TTL + 1)
    assert "run_active" not in adapter._run_streams
    assert (
        adapter._publish_run_event(
            "run_active",
            {
                "event": "run.completed",
                "output": "late complete",
                "usage": {"total_tokens": 3},
            },
        )
        is None
    )
    partial = adapter._run_statuses["run_active"]
    assert partial["status"] == "completed"
    assert partial["event_stream_complete"] is False
    assert partial["last_event_id"] == 0
    assert partial["output"] == "late complete"

    with patch(
        "tools.file_tools._authoritative_workspace_root", return_value=None, create=True
    ):
        assert adapter._run_workspace_root("session") is None
    assert (
        project_tool_start(
            "call", "read_file", {"path": "src/app.py"}, workspace_root=None
        )
        is None
    )
    with tempfile.TemporaryDirectory() as workspace:
        with patch(
            "tools.file_tools._authoritative_workspace_root",
            return_value=workspace,
            create=True,
        ):
            assert adapter._run_workspace_root("session") == workspace

    failures = (
        ("terminal", '{"exit_code":0}', False),
        ("terminal", '{"exit_code":2,"error":"private detail"}', True),
        ("read_file", '{"error":"private body"}', True),
        ("read_file", "ordinary output", False),
    )
    for name, result, expected in failures:
        actual, _ = _detect_tool_failure(name, result)
        assert actual is expected


if __name__ == "__main__":
    main()
