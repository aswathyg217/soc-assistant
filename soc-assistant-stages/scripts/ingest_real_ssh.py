"""Parse REAL sshd 'Failed password' lines and ship them to Splunk's HEC.

Honest time + unique replay ids:
  - source_ts   : parsed from the actual syslog line (the real event time).
  - replay_ts   : when THIS ingest ran (so a replay is never mistaken for live).
  - id          : prefixed with a per-run token, so re-ingesting never collides.
The original log line is preserved verbatim in `message`.

TLS is verified by default. For a self-signed local lab pass --ca-cert <path>
(preferred) or --insecure (explicit opt-out)."""
import argparse, json, re, pathlib, sys, uuid, datetime
import requests

SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")


def parse_source_ts(line, year):
    m = SYSLOG_TS.match(line)
    if not m:
        return None
    try:
        dt = datetime.datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=datetime.timezone.utc).isoformat()
    except ValueError:
        return None


def hec_post(url, headers, verify, payload):
    r = requests.post(url, headers=headers, verify=verify, timeout=15, json=payload)
    if r.status_code != 200:
        raise SystemExit(f"HEC HTTP {r.status_code}: {r.text}")
    try:
        body = r.json()
    except Exception:
        raise SystemExit(f"HEC non-JSON response: {r.text[:200]}")
    if body.get("code", 0) != 0:          # 0 == Success; anything else is a failure
        raise SystemExit(f"HEC rejected event: {body}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logfile", required=True)
    ap.add_argument("--hec-url", required=True)
    ap.add_argument("--hec-token", required=True)
    ap.add_argument("--index", default="soc_logs")
    ap.add_argument("--tenant", default="acme")
    ap.add_argument("--year", type=int, default=datetime.datetime.now().year,
                    help="year for syslog lines (syslog omits it)")
    ap.add_argument("--ca-cert", help="CA bundle for TLS verification (local-lab cert)")
    ap.add_argument("--insecure", action="store_true", help="disable TLS verification (local lab only)")
    a = ap.parse_args()

    verify = a.ca_cert if a.ca_cert else (not a.insecure)
    if a.insecure and not a.ca_cert:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    run_id = uuid.uuid4().hex[:8]                       # unique per ingest run
    replay_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    url = a.hec_url.rstrip("/") + "/services/collector/event"
    headers = {"Authorization": f"Splunk {a.hec_token}"}

    i = 0
    for line in pathlib.Path(a.logfile).read_text().splitlines():
        m = FAILED.search(line)
        if not m:
            continue
        i += 1
        user, ip, _ = m.groups()
        source_ts = parse_source_ts(line, a.year)
        ev = {"id": f"real-ssh-{run_id}-{i:03d}", "tenant": a.tenant,
              "source_ts": source_ts, "replay_ts": replay_ts, "replay_run": run_id,
              "ts": source_ts or replay_ts,                # 'ts' = best-known event time
              "src_ip": ip, "user": user, "user_agent": "sshd",
              "action": "ssh_login_failed", "message": line.strip()}
        hec_post(url, headers, verify,
                 {"index": a.index, "sourcetype": "soc:event", "event": json.dumps(ev)})
    print(f"Ingested {i} REAL sshd failed-login events into '{a.index}' "
          f"(replay_run={run_id}).")


if __name__ == "__main__":
    main()
