import hashlib
import json
from pathlib import Path

FIXTURES = Path(__file__).parents[1] / "fixtures" / "x402"


def _load(name):
    return json.loads((FIXTURES / name).read_text())


def test_x402_v2_fixture_contract_and_hashes():
    required = _load("payment-required.json")
    payload = _load("payment-payload-exact.json")
    settled = _load("settlement-response.json")
    manifest = _load("manifest.json")

    assert required["x402Version"] == payload["x402Version"] == 2
    assert payload["accepted"] == required["accepts"][0]
    assert settled["success"] is True
    assert settled["network"] == payload["accepted"]["network"]
    for name, expected in manifest["files"].items():
        canonical = json.dumps(_load(name), sort_keys=True, separators=(",", ":")).encode()
        assert hashlib.sha256(canonical).hexdigest() == expected["sha256"]
