from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "acedatacloud-container.yml"
SOURCE_SHA = "38b8f3a3b10df7a33753f0b402593c37e0019f32"


def test_acedatacloud_container_is_an_immutable_multiarch_source_build():
    workflow = WORKFLOW.read_text()

    assert f"SOURCE_SHA: {SOURCE_SHA}" in workflow
    assert f"IMAGE_TAG: {SOURCE_SHA}-multiarch.1" in workflow
    assert "ref: ${{ env.SOURCE_SHA }}" in workflow
    assert "docker/setup-qemu-action@v3" in workflow
    assert "'linux/amd64,linux/arm64'" in workflow
    assert "push: ${{ github.event_name != 'pull_request' }}" in workflow
    assert "labels: org.opencontainers.image.revision=${{ env.SOURCE_SHA }}" in workflow
    assert "build-args: HERMES_GIT_SHA=${{ env.SOURCE_SHA }}" in workflow
    assert "Reject an existing immutable tag" in workflow
    assert "manifest unknown|not found" in workflow
    assert "Refusing to overwrite immutable image tag" in workflow
