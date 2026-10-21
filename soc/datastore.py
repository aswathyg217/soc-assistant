"""Loads the synthetic data. Knows nothing about sessions or permissions — it
just returns records. Scoping happens above it, on purpose."""
import json
import pathlib
from typing import Optional

_DATA = pathlib.Path(__file__).resolve().parent.parent / "data"


def _load(name): return json.loads((_DATA / name).read_text())
def all_logs(): return _load("logs.json")
def all_incidents(): return _load("incidents.json")
def all_alerts(): return _load("alerts.json")


def get_alert(alert_id) -> Optional[dict]:
    return next((a for a in all_alerts() if a["id"] == alert_id), None)


def get_incident(incident_id) -> Optional[dict]:
    return next((i for i in all_incidents() if i["id"] == incident_id), None)


def public_alert_view(alert: dict) -> dict:
    """Strip the ground_truth answer key before anything reaches the model."""
    return {k: v for k, v in alert.items() if k != "ground_truth"}
