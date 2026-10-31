"""Ship the synthetic data/logs.json events to Splunk HEC.

TLS verified by default; --ca-cert <path> for a self-signed local cert, or
--insecure to opt out explicitly (local lab only). Checks both the HTTP status
and the HEC body code."""
import argparse, json, pathlib, sys
import requests

_LOGS = pathlib.Path(__file__).resolve().parent.parent / "data" / "logs.json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hec-url", required=True)
    ap.add_argument("--hec-token", required=True)
    ap.add_argument("--index", default="soc_logs")
    ap.add_argument("--ca-cert")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()

    verify = a.ca_cert if a.ca_cert else (not a.insecure)
    if a.insecure and not a.ca_cert:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = a.hec_url.rstrip("/") + "/services/collector/event"
    headers = {"Authorization": f"Splunk {a.hec_token}"}
    sent = 0
    for ev in json.loads(_LOGS.read_text()):
        r = requests.post(url, headers=headers, verify=verify, timeout=15,
                          json={"index": a.index, "sourcetype": "soc:event",
                                "event": json.dumps(ev)})
        if r.status_code != 200:
            print(f"FAILED {ev.get('id')}: HTTP {r.status_code} {r.text}", file=sys.stderr)
            raise SystemExit(1)
        if r.json().get("code", 0) != 0:
            print(f"FAILED {ev.get('id')}: HEC {r.json()}", file=sys.stderr)
            raise SystemExit(1)
        sent += 1
    print(f"Ingested {sent} events into index '{a.index}'")


if __name__ == "__main__":
    main()
