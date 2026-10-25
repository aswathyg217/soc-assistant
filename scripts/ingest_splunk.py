import argparse, json, pathlib, sys, requests, urllib3
urllib3.disable_warnings()
_LOGS = pathlib.Path(__file__).resolve().parent.parent / "data" / "logs.json"

ap = argparse.ArgumentParser()
ap.add_argument("--hec-url", required=True)
ap.add_argument("--hec-token", required=True)
ap.add_argument("--index", default="soc_logs")
a = ap.parse_args()

url = a.hec_url.rstrip("/") + "/services/collector/event"
headers = {"Authorization": f"Splunk {a.hec_token}"}
sent = 0
for ev in json.loads(_LOGS.read_text()):
    r = requests.post(url, headers=headers, verify=False, timeout=15,
                      json={"index": a.index, "sourcetype": "soc:event",
                            "event": json.dumps(ev)})
    if r.status_code != 200:
        print(f"FAILED {ev.get('id')}: {r.status_code} {r.text}", file=sys.stderr)
        raise SystemExit(1)
    sent += 1
print(f"Ingested {sent} events into index '{a.index}'")
