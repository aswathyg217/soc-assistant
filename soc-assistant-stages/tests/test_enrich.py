"""Stage 6: VirusTotal enrichment — validation, offline mock, failure handling,
and gateway routing. Deterministic, no network. Run: python tests/test_enrich.py"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from soc import enrich
from soc.enrich import validate_hash, EICAR_SHA256, VirusTotalClient
from soc.types import Session
from soc.permission import Dispatcher
from soc.policy import PolicyEngine

S = Session("acme", "analyst", "aswathy")


def test_validate_hash():
    assert validate_hash("a"*32) and validate_hash("b"*40) and validate_hash("c"*64)
    assert validate_hash("xyz") is None and validate_hash("a"*31) is None
    assert validate_hash(None) is None and validate_hash("g"*64) is None


def test_mock_eicar_malicious():
    r = enrich.MockReputation().lookup(EICAR_SHA256)
    assert r["ok"] and r["found"] and r["malicious"] > 0 and r["source"] == "offline-mock"


def test_mock_unknown_not_found():
    r = enrich.MockReputation().lookup("f"*64)       # ends in 'f' -> not found
    assert r["ok"] and r["found"] is False


def test_invalid_hash_rejected_before_lookup():
    assert enrich.MockReputation().lookup("not-a-hash")["error"] == "invalid_hash"


def test_live_network_failure_is_structured():
    import requests
    orig = requests.get
    def boom(*a, **k): raise requests.exceptions.ConnectTimeout("down")
    requests.get = boom
    try:
        r = VirusTotalClient("key").lookup(EICAR_SHA256)
    finally:
        requests.get = orig
    assert not r["ok"] and r["error"].startswith("network_error")


def test_dispatcher_routes_through_gate():
    pol = PolicyEngine()
    d = Dispatcher(S, enforce_permissions=True, policy=pol)
    r = d.call("get_file_reputation", file_hash=EICAR_SHA256)
    assert r.ok and r.data["source"] == "offline-mock" and r.data["malicious"] > 0
    assert any(e["tool"] == "get_file_reputation" and e["allowed"] for e in d.audit)


def test_invalid_hash_tool_error_via_gate():
    pol = PolicyEngine()
    d = Dispatcher(S, enforce_permissions=True, policy=pol)
    r = d.call("get_file_reputation", file_hash="xyz")
    assert not r.ok and r.error == "invalid_hash"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    ok = 0
    for fn in fns:
        try: fn(); ok += 1; print("PASS", fn.__name__)
        except Exception: print("FAIL", fn.__name__); traceback.print_exc()
    print(f"\n{ok}/{len(fns)} passed"); sys.exit(0 if ok == len(fns) else 1)
