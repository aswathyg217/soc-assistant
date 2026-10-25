"""Logs from a configurable store (JSON or Splunk); incidents/alerts local JSON.
Set SOC_LOG_BACKEND=splunk to switch."""
import json, os, pathlib
from dotenv import load_dotenv
from .logstore import JSONLogStore, SplunkLogStore

load_dotenv()
_DATA = pathlib.Path(__file__).resolve().parent.parent / "data"


def _make_store():
    if os.getenv("SOC_LOG_BACKEND", "json").lower() == "splunk":
        return SplunkLogStore(
            base_url=os.getenv("SPLUNK_URL", "https://localhost:8089"),
            username=os.getenv("SPLUNK_USER", "admin"),
            password=os.getenv("SPLUNK_PASSWORD", ""),
            index=os.getenv("SPLUNK_INDEX", "soc_logs"))
    return JSONLogStore()


_LOG_STORE = _make_store()


def use_store(store):
    global _LOG_STORE
    _LOG_STORE = store


def _load(name): return json.loads((_DATA / name).read_text())
def all_logs(): return _LOG_STORE.all_logs()
def all_incidents(): return _load("incidents.json")
def all_alerts(): return _load("alerts.json")
def get_alert(alert_id): return next((a for a in all_alerts() if a["id"] == alert_id), None)
def get_incident(incident_id): return next((i for i in all_incidents() if i["id"] == incident_id), None)
def public_alert_view(alert): return {k: v for k, v in alert.items() if k != "ground_truth"}
