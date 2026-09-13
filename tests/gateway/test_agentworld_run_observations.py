from pathlib import Path

from acedata_runtime.observations import (
    project_tool_complete,
    project_tool_start,
    safe_workspace_path,
)


def test_projects_file_read_without_raw_arguments(tmp_path: Path):
    target = tmp_path / "src" / "app.py"
    target.parent.mkdir()
    target.write_text("a\nb\n")
    event = project_tool_start(
        "call_1",
        "read_file",
        {"path": "src/app.py", "start_line": 2},
        workspace_root=tmp_path,
    )
    assert event == {
        "call_id": "call_1",
        "public_observation": {
            "version": 1,
            "tool_id": "workspace.file",
            "action": "read",
            "target": {
                "kind": "workspace_path",
                "label": "src/app.py",
                "line_range": {"start": 2},
            },
        },
    }
    assert "path" not in str(event.keys())


def test_projects_result_metadata_without_result_body(tmp_path: Path):
    event = project_tool_complete(
        "call_2",
        "read_file",
        {"path": "notes.txt"},
        "secret body\nsecond line",
        duration_ms=12,
        workspace_root=tmp_path,
    )
    observation = event["public_observation"]
    assert observation["status"] == "succeeded"
    assert observation["duration_ms"] == 12
    assert observation["result_summary"] == {
        "byte_count": 23,
        "media_type": "text/plain",
        "line_count": 2,
    }
    assert "secret body" not in str(event)


def test_redacts_private_external_and_unsafe_paths(tmp_path: Path):
    assert safe_workspace_path(".env.production", tmp_path) == "[private path]"
    assert safe_workspace_path("../secret.txt", tmp_path) is None
    assert safe_workspace_path("/Users/person/secret.txt", tmp_path) is None
    assert safe_workspace_path("C:\\Users\\person\\secret.txt", tmp_path) is None
    assert safe_workspace_path("https://example.com/a", tmp_path) is None
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    assert safe_workspace_path("link/data.txt", tmp_path) == "[external path]"


def test_command_never_exposes_command_text(tmp_path: Path):
    event = project_tool_start(
        "call_3",
        "bash",
        {"command": "curl -H 'Authorization: Bearer token'"},
        workspace_root=tmp_path,
    )
    assert event["public_observation"] == {
        "version": 1,
        "tool_id": "code.command",
        "action": "execute",
        "target": {"kind": "workspace", "label": "workspace"},
    }
    assert "Bearer" not in str(event)


def test_unknown_tool_has_controlled_identity(tmp_path: Path):
    event = project_tool_complete(
        "x",
        "supplier_private_tool",
        {},
        {"item_count": 4, "raw": "hidden"},
        workspace_root=tmp_path,
    )
    assert event["public_observation"]["tool_id"] == "tool.other"
    assert event["public_observation"]["action"] == "other"
    assert event["public_observation"]["result_summary"] == {"item_count": 4}
    assert "supplier_private_tool" not in str(event)


def test_explicit_unsafe_targets_reject_the_whole_observation(tmp_path: Path):
    unsafe = (
        {"path": "src\\private.py"},
        {"path": "/Users/person/private.py"},
        {"path": "src/../private.py"},
        {"path": "src//game.ts"},
        {"path": "src/./game.ts"},
        {"path": "src/game.ts/"},
        {"path": "src/game.ts", "start_line": 0},
        {"path": "src/game.ts", "start_line": 10_000_001},
        {"path": "src/game.ts", "start_line": 1, "end_line": 10_000_001},
        {"path": "src/game.ts", "end_line": 2},
        {"url": "https://user:pass@example.test/private"},
        {"url": "file:///private"},
        {"url": "http://127.0.0.1/private"},
        {"url": "https://10.0.0.8/private"},
        {"url": "https://runtime/private"},
        {"url": "https://service.namespace.svc/private"},
        {"url": "https://a..example.test/private"},
        {"url": "https://-edge.example.test/private"},
        {"url": "https://edge-.example.test/private"},
    )
    for args in unsafe:
        assert (
            project_tool_start("unsafe", "read_file", args, workspace_root=tmp_path)
            is None
        )


def test_workspace_root_controls_public_relative_path(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    event = project_tool_start(
        "call-root", "read_file", {"path": "src/app.py"}, workspace_root=workspace
    )
    assert event["public_observation"]["target"] == {
        "kind": "workspace_path",
        "label": "src/app.py",
    }


def test_file_target_requires_authoritative_workspace_root():
    assert (
        project_tool_start("call-no-root", "read_file", {"path": "src/app.py"}) is None
    )
    private = project_tool_start("call-private", "read_file", {"path": ".env"})
    assert private["public_observation"]["target"]["label"] == "[private path]"


def test_invalid_explicit_resource_target_rejects_observation(tmp_path: Path):
    assert (
        project_tool_start(
            "call-resource",
            "query",
            {"resource_key": "../private"},
            workspace_root=tmp_path,
        )
        is None
    )


def test_public_hostname_is_reduced_to_dns_name(tmp_path: Path):
    event = project_tool_start(
        "call-url",
        "fetch",
        {"url": "https://docs.example.test/private?token=secret"},
        workspace_root=tmp_path,
    )
    assert event["public_observation"]["target"] == {
        "kind": "hostname",
        "label": "docs.example.test",
    }
    assert "private" not in str(event)
    assert "secret" not in str(event)
