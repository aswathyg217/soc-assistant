"""Replay REAL public log data (Loghub OpenSSH) into Splunk, then triage it.

Honest replay: the original line is preserved verbatim; source_ts comes from the
line itself; replay_ts/replay_run mark this replay; ids are unique per run. We
WAIT until the events are actually searchable (poll, bounded) rather than
sleeping a fixed guess. TLS verified by default (SPLUNK_CA_CERT / SPLUNK_VERIFY_TLS=0
for a local lab).

Usage:  python demo_dataset.py /path/to/openssh.log
"""
import sys, re, json, time, os, uuid, datetime, requests
from dotenv import load_dotenv
from soc.types import Session
from soc.permission import Dispatcher
from soc.llm_backend import GroqBackend
from soc.assistant import Assistant
from soc.logstore import SplunkLogStore
import soc.datastore as ds

load_dotenv()
LOGFILE = sys.argv[1] if len(sys.argv) > 1 else "/tmp/openssh.log"
TARGET_IP = os.getenv("SOC_TARGET_IP", "183.62.140.253")
TENANT = os.getenv("SOC_TENANT", "acme")
HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088")
HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
INDEX = os.getenv("SPLUNK_INDEX", "soc_logs")
YEAR = int(os.getenv("SOC_LOG_YEAR", str(datetime.datetime.now().year)))
TLS = ds._tls_setting()
_store = SplunkLogStore(os.getenv("SPLUNK_URL", "https://localhost:8089"),
                        os.getenv("SPLUNK_USER", "admin"),
                        os.getenv("SPLUNK_PASSWORD", ""), INDEX, **TLS)
verify = _store._verify_arg()

SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")


def source_ts(line):
    m = SYSLOG_TS.match(line)
    if not m:
        return None
    try:
        dt = datetime.datetime.strptime(f"{YEAR} {m.group(1)}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=datetime.timezone.utc).isoformat()
    except ValueError:
        return None


run_id = uuid.uuid4().hex[:8]
replay_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
events, ids = [], []
for line in open(LOGFILE):
    if TARGET_IP not in line:
        continue
    m = FAILED.search(line)
    if not m:
        continue
    u, ip, _ = m.groups()
    n = len(events) + 1
    eid = f"ds-{run_id}-{n:03d}"
    ids.append(eid)
    events.append({"id": eid, "tenant": TENANT, "source_ts": source_ts(line),
                   "replay_ts": replay_ts, "replay_run": run_id,
                   "ts": source_ts(line) or replay_ts, "src_ip": ip, "user": u,
                   "user_agent": "sshd", "action": "ssh_login_failed",
                   "message": line.strip()})
    if len(events) >= 25:
        break

hec = HEC_URL.rstrip("/") + "/services/collector/event"
for ev in events:
    r = requests.post(hec, headers={"Authorization": f"Splunk {HEC_TOKEN}"},
                      verify=verify, timeout=15,
                      json={"index": INDEX, "sourcetype": "soc:event", "event": json.dumps(ev)})
    if r.status_code != 200 or r.json().get("code", 0) != 0:
        raise SystemExit(f"HEC ingest failed: {r.status_code} {r.text}")
print(f"Ingested {len(events)} dataset events from {TARGET_IP} (replay_run={run_id}).")

# Wait until THIS run's events are searchable (bounded poll), not a fixed sleep.
count_spl = (f'search index={INDEX} replay_run="{run_id}" | stats count')
deadline = time.time() + 60
found = 0
while time.time() < deadline:
    rr = requests.post(f"{os.getenv('SPLUNK_URL','https://localhost:8089')}/services/search/jobs/export",
                       auth=(os.getenv("SPLUNK_USER", "admin"), os.getenv("SPLUNK_PASSWORD", "")),
                       verify=verify, timeout=60,
                       data={"search": count_spl, "output_mode": "json", "exec_mode": "oneshot"})
    rows = [json.loads(l)["result"] for l in rr.text.splitlines() if l.strip() and "result" in json.loads(l)]
    found = int(rows[0]["count"]) if rows else 0
    if found >= len(events):
        break
    time.sleep(3)
print(f"Searchable: {found}/{len(events)} events for replay_run={run_id}.")

ds.use_store(_store)
ALERT = {"id": "ALR-DS-1", "tenant": TENANT,
         "rule": "High-volume SSH brute force (public dataset)", "severity": "high",
         "status": "open", "related_log_ids": ids,
         "analyst_task": "Decide whether this alert is a true positive or benign.",
         "ground_truth": "true_positive"}
_o = ds.get_alert
ds.get_alert = lambda a: ALERT if a == "ALR-DS-1" else _o(a)
s = Session(TENANT, "analyst", "aswathy")
d = Dispatcher(s, enforce_permissions=True)
res = Assistant(s, GroqBackend(), d).triage(ALERT)
print("Verdict  :", res["verdict"]["label"], "(expected true_positive)")
print("Rationale:", res["verdict"]["rationale"])
