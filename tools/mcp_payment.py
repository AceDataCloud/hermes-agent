"""Session-scoped x402 MCP payment challenge and credential bridge."""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

_X402_META_KEY = "x402/payment"
_payment_context: contextvars.ContextVar[tuple[str, str] | None] = contextvars.ContextVar(
    "mcp_payment_context", default=None
)
_lock = threading.RLock()
_waits: dict[tuple[str, str], "PaymentWait"] = {}
_notifiers: dict[str, Callable[[dict[str, Any]], None]] = {}


class PaymentRetryUncertain(RuntimeError):
    """A credential-bearing MCP request failed and must never be replayed automatically."""


@dataclass
class PaymentWait:
    session_key: str
    tool_call_id: str
    server_name: str
    tool_name: str
    arguments_digest: str
    challenge_digest: str
    payment_required: dict[str, Any]
    event: threading.Event
    payment_payload: dict[str, Any] | None = None
    state: str = "waiting"
    updated_at: float = 0.0


def set_payment_context(session_key: str, tool_call_id: str):
    return _payment_context.set((session_key or "", tool_call_id or ""))


def reset_payment_context(token) -> None:
    _payment_context.reset(token)


def register_payment_notifier(session_key: str, callback: Callable[[dict[str, Any]], None]) -> None:
    with _lock:
        _notifiers[session_key] = callback


def payment_notifier_registered(session_key: str) -> bool:
    with _lock:
        return bool(session_key and session_key in _notifiers)


def unregister_payment_notifier(session_key: str) -> None:
    with _lock:
        _notifiers.pop(session_key, None)
        for wait in [wait for wait in _waits.values() if wait.session_key == session_key]:
            wait.payment_payload = None
            if wait.state not in {"consumed", "expired", "failed"}:
                wait.state = "cancelled"
                wait.updated_at = time.time()
                wait.event.set()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _challenge(result: Any) -> tuple[dict[str, Any], str] | None:
    if not bool(getattr(result, "isError", getattr(result, "is_error", False))):
        return None
    structured = getattr(result, "structuredContent", getattr(result, "structured_content", None))
    if not isinstance(structured, dict) or structured.get("x402Version") != 2:
        return None
    accepts = structured.get("accepts")
    if not isinstance(accepts, list) or not accepts:
        return None
    texts = [getattr(block, "text", None) for block in (getattr(result, "content", None) or [])]
    text = "".join(value for value in texts if isinstance(value, str)).strip()
    try:
        mirrored = json.loads(text)
    except (TypeError, ValueError):
        return None
    if mirrored != structured:
        raise ValueError("x402 PaymentRequired text and structuredContent differ")
    digest = hashlib.sha256(_canonical(structured)).hexdigest()
    return structured, digest


async def await_payment_and_retry(
    result: Any,
    *,
    server_name: str,
    tool_name: str,
    arguments: dict[str, Any],
    retry: Callable[[dict[str, Any]], Any],
    timeout: float,
) -> Any:
    parsed = _challenge(result)
    if parsed is None:
        return result
    context = _payment_context.get()
    if not context or not all(context):
        return result
    session_key, tool_call_id = context
    payment_required, challenge_digest = parsed
    arguments_digest = hashlib.sha256(_canonical(arguments)).hexdigest()
    key = (session_key, tool_call_id)
    with _lock:
        notifier = _notifiers.get(session_key)
        if notifier is None:
            return result
        existing = _waits.get(key)
        if existing is not None:
            if (
                existing.challenge_digest != challenge_digest
                or existing.arguments_digest != arguments_digest
                or existing.tool_name != tool_name
            ):
                raise RuntimeError("x402 payment wait identity changed")
            wait = existing
        else:
            wait = PaymentWait(
                session_key=session_key,
                tool_call_id=tool_call_id,
                server_name=server_name,
                tool_name=tool_name,
                arguments_digest=arguments_digest,
                challenge_digest=challenge_digest,
                payment_required=payment_required,
                event=threading.Event(),
                updated_at=time.time(),
            )
            _waits[key] = wait
    notifier(
        {
            "tool_call_id": tool_call_id,
            "server_name": server_name,
            "tool_name": tool_name,
            "arguments_digest": arguments_digest,
            "challenge_digest": challenge_digest,
            "payment_required": payment_required,
        }
    )
    signaled = await asyncio.to_thread(wait.event.wait, max(0.0, timeout))
    with _lock:
        if not signaled and wait.payment_payload is None and wait.state == "waiting":
            wait.state = "expired"
            wait.updated_at = time.time()
            raise TimeoutError("x402 payment credential wait expired")
        payload = wait.payment_payload
        if wait.state == "cancelled" or payload is None:
            raise RuntimeError("x402 payment wait was cancelled")
        wait.state = "resuming"
        wait.updated_at = time.time()
    try:
        retried = await retry({_X402_META_KEY: payload})
    except BaseException as exc:
        with _lock:
            wait.state = "failed"
            wait.payment_payload = None
            wait.updated_at = time.time()
        raise PaymentRetryUncertain("credential-bearing MCP retry outcome is uncertain") from exc
    with _lock:
        wait.state = "consumed"
        wait.payment_payload = None
        wait.updated_at = time.time()
    return retried


def submit_payment(
    session_key: str,
    tool_call_id: str,
    challenge_digest: str,
    payment_payload: dict[str, Any],
) -> tuple[str, bool]:
    if (
        not isinstance(payment_payload, dict)
        or payment_payload.get("x402Version") != 2
        or not isinstance(payment_payload.get("accepted"), dict)
        or not isinstance(payment_payload.get("payload"), dict)
        or not payment_payload["payload"]
    ):
        raise ValueError("invalid x402 PaymentPayload")
    key = (session_key, tool_call_id)
    with _lock:
        wait = _waits.get(key)
        if wait is None:
            raise KeyError("payment wait not found")
        if wait.challenge_digest != challenge_digest:
            raise ValueError("payment challenge digest mismatch")
        if payment_payload["accepted"] not in wait.payment_required["accepts"]:
            raise ValueError("PaymentPayload accepted requirement was not offered")
        if wait.state in {"cancelled", "expired", "failed"}:
            raise RuntimeError("payment wait is not active")
        if wait.state in {"submitted", "resuming", "consumed"}:
            return wait.state, False
        wait.payment_payload = payment_payload
        wait.state = "submitted"
        wait.updated_at = time.time()
        wait.event.set()
        return wait.state, True


def cancel_payment_waits(session_key: str) -> None:
    with _lock:
        waits = [wait for (scope, _), wait in _waits.items() if scope == session_key]
        for wait in waits:
            if wait.state not in {"consumed", "expired"}:
                wait.state = "cancelled"
                wait.updated_at = time.time()
                wait.event.set()


def payment_wait_snapshot(session_key: str, tool_call_id: str) -> dict[str, Any] | None:
    with _lock:
        wait = _waits.get((session_key, tool_call_id))
        if wait is None:
            return None
        return {
            "tool_call_id": wait.tool_call_id,
            "server_name": wait.server_name,
            "tool_name": wait.tool_name,
            "arguments_digest": wait.arguments_digest,
            "challenge_digest": wait.challenge_digest,
            "payment_required": wait.payment_required,
            "state": wait.state,
        }


def prune_payment_waits(max_age_seconds: float = 900.0) -> int:
    cutoff = time.time() - max(0.0, max_age_seconds)
    with _lock:
        keys = [
            key for key, wait in _waits.items()
            if wait.state in {"consumed", "cancelled", "expired", "failed"} and wait.updated_at <= cutoff
        ]
        for key in keys:
            _waits.pop(key, None)
        return len(keys)

_request_meta: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "mcp_request_meta", default={}
)


def set_request_meta(meta: dict[str, Any]):
    return _request_meta.set(dict(meta))


def reset_request_meta(token) -> None:
    _request_meta.reset(token)


def request_meta(extra: dict[str, Any] | None = None) -> dict[str, Any] | None:
    merged = dict(_request_meta.get())
    if extra:
        merged.update(extra)
    return merged or None
