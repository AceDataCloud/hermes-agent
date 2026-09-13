import asyncio
import json
from types import SimpleNamespace

import pytest

from tools.mcp_payment import (
    await_payment_and_retry,
    register_payment_notifier,
    reset_payment_context,
    set_payment_context,
    submit_payment,
    unregister_payment_notifier,
)


def _challenge(payload):
    return SimpleNamespace(
        isError=True,
        structuredContent=payload,
        content=[SimpleNamespace(text=json.dumps(payload, separators=(",", ":")))],
    )


@pytest.mark.asyncio
async def test_challenge_waits_and_retries_with_transport_meta():
    required = {
        "x402Version": 2,
        "resource": {"url": "mcp://song"},
        "accepts": [{"scheme": "exact", "network": "eip155:84532", "amount": "1"}],
    }
    payload = {"x402Version": 2, "accepted": required["accepts"][0], "payload": {"signature": "test"}}
    notices = []
    register_payment_notifier("run-1", notices.append)
    token = set_payment_context("run-1", "call-1")

    async def retry(meta):
        assert meta == {"x402/payment": payload}
        return SimpleNamespace(isError=False, content=[SimpleNamespace(text="task-1")])

    try:
        task = asyncio.create_task(
            await_payment_and_retry(
                _challenge(required), server_name="paid", tool_name="song_generate",
                arguments={"prompt": "x"}, retry=retry, timeout=1,
            )
        )
        await asyncio.sleep(0)
        assert notices and "payment_payload" not in notices[0]
        state, changed = submit_payment("run-1", "call-1", notices[0]["challenge_digest"], payload)
        assert (state, changed) == ("submitted", True)
        result = await task
        assert result.content[0].text == "task-1"
    finally:
        reset_payment_context(token)
        unregister_payment_notifier("run-1")


@pytest.mark.asyncio
async def test_non_x402_error_passes_through():
    result = SimpleNamespace(isError=True, structuredContent={"code": "bad"}, content=[])
    retried = False

    async def retry(_meta):
        nonlocal retried
        retried = True

    assert await await_payment_and_retry(
        result, server_name="s", tool_name="t", arguments={}, retry=retry, timeout=0.01
    ) is result
    assert not retried


@pytest.mark.asyncio
async def test_mismatched_mirror_fails_closed():
    result = SimpleNamespace(
        isError=True,
        structuredContent={"x402Version": 2, "accepts": [{}]},
        content=[SimpleNamespace(text='{"x402Version":2,"accepts":[{"different":true}]}')],
    )
    with pytest.raises(ValueError, match="differ"):
        await await_payment_and_retry(
            result, server_name="s", tool_name="t", arguments={}, retry=lambda _: None, timeout=0.01
        )


def test_submit_rejects_unoffered_requirement():
    from tools.mcp_payment import _waits, PaymentWait, submit_payment
    import threading

    _waits[("run-u", "call-u")] = PaymentWait(
        session_key="run-u", tool_call_id="call-u", server_name="s", tool_name="t",
        arguments_digest="a", challenge_digest="b" * 64,
        payment_required={"accepts": [{"scheme": "exact", "amount": "1"}]},
        event=threading.Event(),
    )
    with pytest.raises(ValueError, match="not offered"):
        submit_payment(
            "run-u", "call-u", "b" * 64,
            {"x402Version": 2, "accepted": {"scheme": "exact", "amount": "2"}, "payload": {"x": 1}},
        )
    _waits.pop(("run-u", "call-u"), None)


@pytest.mark.asyncio
async def test_retry_failure_clears_payment_payload():
    from tools.mcp_payment import PaymentRetryUncertain, _waits

    required = {"x402Version": 2, "accepts": [{"scheme": "exact", "amount": "1"}]}
    payload = {"x402Version": 2, "accepted": required["accepts"][0], "payload": {"secret": "x"}}
    notices = []
    register_payment_notifier("run-f", notices.append)
    token = set_payment_context("run-f", "call-f")

    async def retry(_meta):
        raise RuntimeError("retry failed")

    try:
        task = asyncio.create_task(await_payment_and_retry(
            _challenge(required), server_name="s", tool_name="t", arguments={}, retry=retry, timeout=1,
        ))
        await asyncio.sleep(0)
        submit_payment("run-f", "call-f", notices[0]["challenge_digest"], payload)
        with pytest.raises(PaymentRetryUncertain, match="outcome is uncertain") as caught:
            await task
        assert isinstance(caught.value.__cause__, RuntimeError)
        wait = _waits[("run-f", "call-f")]
        assert wait.state == "failed"
        assert wait.payment_payload is None
    finally:
        reset_payment_context(token)
        unregister_payment_notifier("run-f")


def test_failed_wait_rejects_late_credential():
    from tools.mcp_payment import _waits, PaymentWait
    import threading

    _waits[("run-l", "call-l")] = PaymentWait(
        session_key="run-l", tool_call_id="call-l", server_name="s", tool_name="t",
        arguments_digest="a", challenge_digest="c" * 64,
        payment_required={"accepts": [{"scheme": "exact"}]}, event=threading.Event(), state="failed",
    )
    with pytest.raises(RuntimeError, match="not active"):
        submit_payment(
            "run-l", "call-l", "c" * 64,
            {"x402Version": 2, "accepted": {"scheme": "exact"}, "payload": {"x": 1}},
        )
    _waits.pop(("run-l", "call-l"), None)


def test_x402_response_metadata_is_host_only():
    from tools.mcp_tool_content import _strip_reserved_meta_keys

    assert _strip_reserved_meta_keys({"x402/payment": {"signature": "secret"}, "vendor/example": 1}) == {
        "vendor/example": 1
    }


def test_request_meta_merges_grant_and_payment_without_mutation():
    from tools.mcp_payment import request_meta, reset_request_meta, set_request_meta

    token = set_request_meta({"agentworld/grant": "signed"})
    try:
        assert request_meta() == {"agentworld/grant": "signed"}
        assert request_meta({"x402/payment": {"x402Version": 2}}) == {
            "agentworld/grant": "signed",
            "x402/payment": {"x402Version": 2},
        }
        assert request_meta() == {"agentworld/grant": "signed"}
    finally:
        reset_request_meta(token)
