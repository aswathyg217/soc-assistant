import os, json, requests, urllib3
from dotenv import load_dotenv
from soc.types import Session
from soc.permission import Dispatcher
from soc.llm_backend import GroqBackend
from soc.assistant import Assistant
from soc.logstore import SplunkLogStore
import soc.datastore as ds
load_dotenv(); urllib3.disable_warnings()
URL=os.getenv("SPLUNK_URL","https://localhost:8089"); USER=os.getenv("SPLUNK_USER","admin")
PW=os.getenv("SPLUNK_PASSWORD",""); INDEX=os.getenv("SPLUNK_INDEX","soc_logs")
DET=(f"search index={INDEX} | spath | search action=ssh_login_failed "
     "| stats count values(id) as ids values(user) as users dc(user) as nusers by src_ip "
     "| where count>=5 | sort - count | head 1")
r=requests.post(f"{URL}/services/search/jobs/export",auth=(USER,PW),verify=False,timeout=60,
                data={"search":DET,"output_mode":"json","exec_mode":"oneshot"})
r.raise_for_status()
rows=[json.loads(l)["result"] for l in r.text.splitlines() if l.strip()]
if not rows: print("Splunk detected no brute force."); raise SystemExit(0)
det=rows[0]; ip=det["src_ip"]; c=int(det["count"])
ids=det["ids"] if isinstance(det["ids"],list) else [det["ids"]]
print(f"SPLUNK DETECTION -> brute force from {ip}: {c} failed logins, {det.get('nusers')} usernames.\n")
ds.use_store(SplunkLogStore(URL,USER,PW,INDEX))
ALERT={"id":"ALR-SPL-1","tenant":"acme","rule":f"SSH brute force from {ip} ({c} failures) - detected by Splunk",
       "severity":"high","status":"open","related_log_ids":ids,
       "analyst_task":"Decide whether this alert is a true positive or benign.","ground_truth":"true_positive"}
_o=ds.get_alert; ds.get_alert=lambda a: ALERT if a=="ALR-SPL-1" else _o(a)
s=Session("acme","analyst","aswathy"); d=Dispatcher(s,enforce_permissions=True)
res=Assistant(s,GroqBackend(),d).triage(ALERT)
print("Tools    :",[e["tool"] for e in d.audit])
print("Verdict  :",res["verdict"]["label"],"(expected true_positive)")
print("Rationale:",res["verdict"]["rationale"])
