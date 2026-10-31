"""Logs from a configurable store (JSON or Splunk); incidents/alerts local JSON.
Set SOC_LOG_BACKEND=splunk to switch.

TLS for Splunk is VERIFIED by default. For a self-signed local lab, set
SPLUNK_CA_CERT to the Splunk cert path (preferred), or set SPLUNK_VERIFY_TLS=0
to disable verification explicitly (local lab only)."""
import json, os, pathlib
from dotenv import load_dotenv
from .logstore import JSONLogStore, SplunkLogStore

load_dotenv()
_DATA = pathlib.Path(__file__).resolve().parent.parent / "data"


def _tls_setting():
    ca = os.getenv("SPLUNK_CA_CERT")
    if ca:
        return {"ca_cert": ca}
    if os.getenv("SPLUNK_VERIFY_TLS", "1").lower() in ("0", "false", "no"):
        return {"verify_tls": False}      # explicit local-lab opt-out
    return {"verify_tls": True}


def _make_store():
    if os.getenv("SOC_LOG_BACKEND", "json").lower() == "splunk":
        return SplunkLogStore(
            base_url=os.getenv("SPLUNK_URL", "https://localhost:8089"),
            username=os.getenv("SPLUNK_USER", "admin"),
            password=os.getenv("SPLUNK_PASSWORD", ""),
            index=os.getenv("SPLUNK_INDEX", "soc_logs"),
            **_tls_setting())
    return JSONLogStore()


_LOG_STORE = _make_store()


def use_store(store):
    global _LOG_STORE
    _LOG_STORE = store


def _load(name): return json.loads((_DATA / name).read_text())


def all_logs(tenant=None, earliest=None, latest=None, max_count=10000):
    return _LOG_STORE.all_logs(tenant=tenant, earliest=earliest,
                               latest=latest, max_count=max_count)


def all_incidents(): return _load("incidents.json")
def all_alerts(): return _load("alerts.json")
def get_alert(alert_id): return next((a for a in all_alerts() if a["id"] == alert_id), None)
def get_incident(incident_id): return next((i for i in all_incidents() if i["id"] == incident_id), None)
def public_alert_view(alert): return {k: v for k, v in alert.items() if k != "ground_truth"}
