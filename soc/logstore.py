"""Log source behind one interface: JSON (default) or Splunk."""
import json, pathlib
from typing import Protocol


class LogStore(Protocol):
    def all_logs(self) -> list: ...


class JSONLogStore:
    def __init__(self, path=None):
        if path is None:
            path = pathlib.Path(__file__).resolve().parent.parent / "data" / "logs.json"
        self.path = pathlib.Path(path)

    def all_logs(self):
        return json.loads(self.path.read_text())


class SplunkLogStore:
    def __init__(self, base_url, username, password, index="soc_logs", verify_tls=False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.index = index
        self.verify_tls = verify_tls

    def all_logs(self):
        import requests, urllib3
        urllib3.disable_warnings()
        r = requests.post(f"{self.base_url}/services/search/jobs/export",
                          auth=(self.username, self.password),
                          data={"search": f"search index={self.index}",
                                "output_mode": "json", "exec_mode": "oneshot"},
                          verify=self.verify_tls, timeout=60)
        r.raise_for_status()
        events = []
        for line in r.text.splitlines():
            if not line.strip():
                continue
            raw = json.loads(line).get("result", {}).get("_raw")
            if raw:
                try:
                    events.append(json.loads(raw))
                except Exception:
                    pass
        return events
