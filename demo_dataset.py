import sys, re, json, time, os, requests, urllib3
from dotenv import load_dotenv
from soc.types import Session
from soc.permission import Dispatcher
from soc.llm_backend import GroqBackend
from soc.assistant import Assistant
from soc.logstore import SplunkLogStore
import soc.datastore as ds
load_dotenv(); urllib3.disable_warnings()
LOGFILE=sys.argv[1] if len(sys.argv)>1 else "/tmp/openssh.log"
TARGET_IP="183.62.140.253"; HEC_URL="https://localhost:8088"
HEC_TOKEN=os.getenv("SPLUNK_HEC_TOKEN",""); INDEX=os.getenv("SPLUNK_INDEX","soc_logs")
pat=re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
events=[]
for line in open(LOGFILE):
    if TARGET_IP not in line: continue
    m=pat.search(line)
    if not m: continue
    u,ip,_=m.groups()
    events.append({"id":f"ds-{len(events)+1:03d}","tenant":"acme","ts":"2026-12-10T07:00:00Z",
                   "src_ip":ip,"user":u,"user_agent":"sshd","action":"ssh_login_failed","message":line.strip()})
    if len(events)>=25: break
url=HEC_URL.rstrip("/")+"/services/collector/event"
for ev in events:
    requests.post(url,headers={"Authorization":f"Splunk {HEC_TOKEN}"},verify=False,timeout=15,
                  json={"index":INDEX,"sourcetype":"soc:event","event":json.dumps(ev)})
print(f"Ingested {len(events)} REAL dataset events from {TARGET_IP} into Splunk."); time.sleep(15)
ds.use_store(SplunkLogStore(os.getenv("SPLUNK_URL","https://localhost:8089"),
    os.getenv("SPLUNK_USER","admin"),os.getenv("SPLUNK_PASSWORD",""),INDEX))
ALERT={"id":"ALR-DS-1","tenant":"acme","rule":"High-volume SSH brute force (public dataset)",
       "severity":"high","status":"open","related_log_ids":[f"ds-{i:03d}" for i in range(1,26)],
       "analyst_task":"Decide whether this alert is a true positive or benign.","ground_truth":"true_positive"}
_o=ds.get_alert; ds.get_alert=lambda a: ALERT if a=="ALR-DS-1" else _o(a)
s=Session("acme","analyst","aswathy"); d=Dispatcher(s,enforce_permissions=True)
r=Assistant(s,GroqBackend(),d).triage(ALERT)
print("Verdict  :",r["verdict"]["label"],"(expected true_positive)")
print("Rationale:",r["verdict"]["rationale"])
