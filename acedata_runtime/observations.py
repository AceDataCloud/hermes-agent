from __future__ import annotations

import hashlib
import ipaddress
import mimetypes
import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

MAX_PATH_LENGTH = 512
MAX_LOCATIONS = 8
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SECRET_RE = re.compile(
    r"(^|/)(?:\.env(?:\..*)?|\.ssh|\.aws|\.config|secrets?|credentials?|tokens?|private_keys?)(?:/|$)",
    re.IGNORECASE,
)
COUNT_KEYS = {
    "item_count",
    "byte_count",
    "created_count",
    "updated_count",
    "deleted_count",
    "affected_count",
    "match_count",
    "line_count",
}

TOOL_RULES = (
    (("read_file", "read_text", "read"), "workspace.file", "read"),
    (
        ("write_file", "write_text", "replace", "edit_file", "patch"),
        "workspace.file",
        "update",
    ),
    (("delete_file", "remove_file"), "workspace.file", "delete"),
    (("list_dir", "directory", "glob"), "workspace.directory", "list"),
    (("browser", "playwright", "page"), "browser.page", "navigate"),
    (("web_search", "search_web", "search"), "web.search", "search"),
    (("fetch", "http_get", "download"), "web.fetch", "fetch"),
    (
        ("bash", "shell", "terminal", "python", "command", "execute"),
        "code.command",
        "execute",
    ),
    (("query", "sql", "database"), "data.query", "inspect"),
    (("delegate", "subagent", "spawn_agent"), "agent.delegation", "delegate"),
)
PATH_KEYS = ("path", "file_path", "filename", "directory", "cwd", "target")
URL_KEYS = ("url", "uri", "href")


def _tool_identity(name: Any) -> tuple[str, str]:
    normalized = re.sub(r"[^a-z0-9_]+", "_", str(name or "").lower())[:128]
    for needles, tool_id, action in TOOL_RULES:
        if any(needle in normalized for needle in needles):
            return tool_id, action
    return "tool.other", "other"


def _workspace_root(workspace_root: str | os.PathLike[str]) -> Path:
    value = Path(workspace_root).expanduser()
    try:
        return value.resolve(strict=True)
    except (OSError, RuntimeError):
        return value.resolve(strict=False)


def safe_workspace_path(
    value: Any, workspace_root: str | os.PathLike[str] | None
) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_PATH_LENGTH
        or CONTROL_RE.search(value)
    ):
        return None
    if "\\" in value or "://" in value or value.startswith(("~", "//", "\\")):
        return None
    windows = PureWindowsPath(value)
    raw_parts = value.split("/")
    posix = PurePosixPath(value)
    if (
        windows.drive
        or windows.is_absolute()
        or posix.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        return None
    cleaned = str(posix)
    if cleaned in {"", "."}:
        return None
    if SECRET_RE.search(f"/{cleaned}"):
        return "[private path]"
    if workspace_root is None:
        return None
    root = _workspace_root(workspace_root)
    candidate = root.joinpath(*posix.parts)
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return "[external path]"
    return resolved.relative_to(root).as_posix()


def _safe_hostname(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 2048 or CONTROL_RE.search(value):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return None
    hostname = parsed.hostname.lower().rstrip(".")
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 2
        or hostname.endswith((".local", ".internal", ".localhost", ".svc"))
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        )
    ):
        return None
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    return None


def _line_range(args: dict[str, Any]) -> dict[str, int] | None:
    start_present = any(key in args for key in ("start_line", "line_start", "offset"))
    end_present = any(key in args for key in ("end_line", "line_end"))
    if not start_present and not end_present:
        return None
    start = args.get("start_line", args.get("line_start", args.get("offset")))
    end = args.get("end_line", args.get("line_end"))
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not 1 <= start <= 10_000_000
    ):
        raise ValueError("unsafe line range")
    result = {"start": start}
    if end_present:
        if (
            not isinstance(end, int)
            or isinstance(end, bool)
            or not start <= end <= 10_000_000
        ):
            raise ValueError("unsafe line range")
        result["end"] = end
    return result


def _target(
    args: Any, tool_id: str, workspace_root: str | os.PathLike[str] | None
) -> dict[str, Any] | None:
    if not isinstance(args, dict):
        return (
            {"kind": "workspace", "label": "workspace"}
            if tool_id == "code.command"
            else None
        )
    for key in PATH_KEYS:
        if key not in args:
            continue
        path = safe_workspace_path(args.get(key), workspace_root)
        if path is None:
            raise ValueError("unsafe workspace path")
        result: dict[str, Any] = {"kind": "workspace_path", "label": path}
        lines = _line_range(args)
        if lines:
            result["line_range"] = lines
        return result
    for key in URL_KEYS:
        if key not in args:
            continue
        hostname = _safe_hostname(args.get(key))
        if hostname is None:
            raise ValueError("unsafe public URL")
        return {"kind": "hostname", "label": hostname}
    if "resource_key" in args:
        resource = args.get("resource_key")
        if not isinstance(resource, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", resource
        ):
            raise ValueError("unsafe resource key")
        return {"kind": "resource", "label": resource}
    if tool_id == "code.command":
        return {"kind": "workspace", "label": "workspace"}
    return None


def _positive_int(value: Any) -> int | None:
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 1_000_000_000
    ):
        return value
    return None


def _summary(value: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if isinstance(value, dict):
        for key in COUNT_KEYS:
            count = _positive_int(value.get(key))
            if count is not None:
                result[key] = count
        media_type = value.get("media_type")
        if isinstance(media_type, str) and re.fullmatch(
            r"[a-z0-9.+-]+/[a-z0-9.+-]+", media_type.lower()
        ):
            result["media_type"] = media_type.lower()[:127]
        digest = value.get("content_hash")
        if isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            result["content_hash"] = digest
    elif isinstance(value, (list, tuple)):
        result["item_count"] = min(len(value), 1_000_000_000)
    elif isinstance(value, (bytes, bytearray)):
        result["byte_count"] = len(value)
        result["content_hash"] = f"sha256:{hashlib.sha256(value).hexdigest()}"
    elif isinstance(value, str):
        encoded = value.encode("utf-8", errors="replace")
        result["byte_count"] = len(encoded)
    return result


def _augment_file_summary(
    summary: dict[str, Any], target: dict[str, Any] | None, result: Any
) -> None:
    if not target or target.get("kind") != "workspace_path":
        return
    label = target.get("label")
    if not isinstance(label, str) or label.startswith("["):
        return
    media_type, _ = mimetypes.guess_type(label)
    if media_type:
        summary.setdefault("media_type", media_type)
    if isinstance(result, str):
        summary.setdefault("line_count", min(result.count("\n") + 1, 1_000_000_000))


def project_tool_start(
    call_id: Any,
    name: Any,
    args: Any,
    *,
    workspace_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(call_id, str) or not re.fullmatch(
        r"[A-Za-z0-9._:-]{1,255}", call_id
    ):
        return None
    tool_id, action = _tool_identity(name)
    try:
        target = _target(args, tool_id, workspace_root)
    except ValueError:
        return None
    observation: dict[str, Any] = {"version": 1, "tool_id": tool_id, "action": action}
    if target:
        observation["target"] = target
    summary = _summary(args)
    if summary:
        observation["input_summary"] = summary
    return {"call_id": call_id, "public_observation": observation}


def project_tool_complete(
    call_id: Any,
    name: Any,
    args: Any,
    result: Any,
    *,
    duration_ms: Any = None,
    is_error: bool = False,
    workspace_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any] | None:
    projected = project_tool_start(call_id, name, args, workspace_root=workspace_root)
    if projected is None:
        return None
    observation = projected["public_observation"]
    summary = _summary(result)
    _augment_file_summary(summary, observation.get("target"), result)
    status = "failed" if is_error else "succeeded"
    observation["status"] = status
    if summary:
        observation["result_summary"] = summary
    duration = _positive_int(duration_ms)
    if duration is not None:
        observation["duration_ms"] = duration
    if is_error:
        observation["failure_category"] = "tool_error"
    return projected
