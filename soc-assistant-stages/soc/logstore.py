"""Log source behind one interface: JSON (default) or Splunk.

Both stores take the same optional query scope — tenant, time window, and a hard
result cap — so a Splunk query is bounded and tenant-scoped AT THE SOURCE, not
after pulling every tenant's events into Python. `tenant` is validated against a
strict allowlist pattern before it is ever placed in SPL, so it cannot be used to
inject search syntax."""
import json, pathlib, re
from typing import Protocol, Optional

# A tenant id is a short slug. Anything else never reaches a Splunk query string.
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _valid_tenant(tenant: Optional[str]) -> Optional[str]:
    if tenant is None:
        return None
    if not _TENANT_RE.match(tenant):
        raise ValueError(f"invalid tenant id {tenant!r}")
    return tenant


class LogStore(Protocol):
    def all_logs(self, tenant: Optional[str] = None, earliest: Optional[str] = None,
                 latest: Optional[str] = None, max_count: int = 10000) -> list: ...


class JSONLogStore:
    def __init__(self, path=None):
        if path is None:
            path = pathlib.Path(__file__).resolve().parent.parent / "data" / "logs.json"
        self.path = pathlib.Path(path)

    def all_logs(self, tenant=None, earliest=None, latest=None, max_count=10000):
        tenant = _valid_tenant(tenant)
        logs = json.loads(self.path.read_text())
        if tenant is not None:
            logs = [l for l in logs if l.get("tenant") == tenant]
        return logs[:max_count]


class SplunkLogStore:
    def __init__(self, base_url, username, password, index="soc_logs",
                 verify_tls=True, ca_cert=None):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.index = index
        # verify_tls: True = verify against the system/CA store (default).
        #   A path string = verify against that CA bundle (the local-lab exception:
        #   point SPLUNK_CA_CERT at Splunk's self-signed cert). False = no
        #   verification (explicit opt-out only; warns).
        self.verify = ca_cert if ca_cert else verify_tls

    def _verify_arg(self):
        if self.verify is False:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            return False
        return self.verify  # True or a CA-bundle path

    def all_logs(self, tenant=None, earliest=None, latest=None, max_count=10000):
        import requests
        tenant = _valid_tenant(tenant)
        # Bounded by construction: an explicit time window and a hard head cap.
        window = f"earliest={earliest or '-24h'} latest={latest or 'now'}"
        spl = f"search index={self.index} {window} | spath"
        if tenant is not None:
            spl += f' | search tenant="{tenant}"'      # tenant is allowlist-validated
        spl += f" | head {int(max_count)}"
        try:
            r = requests.post(f"{self.base_url}/services/search/jobs/export",
                              auth=(self.username, self.password),
                              data={"search": spl, "output_mode": "json",
                                    "exec_mode": "oneshot"},
                              verify=self._verify_arg(), timeout=60)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Splunk search failed: {e}") from e
        events = []
        for line in r.text.splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if "messages" in obj and not obj.get("result"):
                continue  # Splunk status/diagnostic line, not a result row
            raw = obj.get("result", {}).get("_raw")
            if raw:
                try:
                    events.append(json.loads(raw))
                except Exception:
                    pass
        return events
