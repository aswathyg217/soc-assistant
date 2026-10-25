import argparse, json, re, pathlib, sys, requests, urllib3
urllib3.disable_warnings()
ap = argparse.ArgumentParser()
ap.add_argument("--logfile", required=True)
ap.add_argument("--hec-url", required=True)
ap.add_argument("--hec-token", required=True)
ap.add_argument("--index", default="soc_logs")
a = ap.parse_args()

pat = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
url = a.hec_url.rstrip("/") + "/services/collector/event"
headers = {"Authorization": f"Splunk {a.hec_token}"}
i = 0
for line in pathlib.Path(a.logfile).read_text().splitlines():
    m = pat.search(line)
    if not m:
        continue
    i += 1
    user, ip, _ = m.groups()
    ev = {"id": f"real-ssh-{i:02d}", "tenant": "acme", "ts": "2026-10-25T17:22:00Z",
          "src_ip": ip, "user": user, "user_agent": "sshd",
          "action": "ssh_login_failed", "message": line.strip()}
    r = requests.post(url, headers=headers, verify=False, timeout=15,
                      json={"index": a.index, "sourcetype": "soc:event", "event": json.dumps(ev)})
    if r.status_code != 200:
        print(f"FAILED: {r.status_code} {r.text}", file=sys.stderr); raise SystemExit(1)
print(f"Ingested {i} REAL SSH failed-login events into '{a.index}'")
