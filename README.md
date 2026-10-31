# Prompt-Injection-Resistant SOC Assistant

Measuring defences against **indirect prompt injection** in an LLM-based
SOC alert-triage assistant. The thesis: *the model proposes, the policy disposes* —
security that does not depend on the model behaving.

## Research question
Under indirect prompt injection hidden in log data, do prompt-level defences (C1)
or an independent tool-permission layer (C2) better prevent unauthorized actions,
while preserving benign investigations?

## Key results (GPT-OSS-20B via Groq)

**Leak attack** (cross-tenant data read) — 3 runs, mean ± spread:

| Config | Fooled | Leaked | Benign kept |
|---|---|---|---|
| C0 | 53±9% | 53±9% | 100% |
| C1 | 40±16% | 40±16% | 100% |
| C2 | 60±0% | **0±0%** | 100% |
| C1+C2 | 33±9% | **0±0%** | 100% |

**Suppression attack** (dismissing a genuine alert) — 2 runs:

| Config | Suppressed |
|---|---|
| C0 | 100% |
| C1 | 88% |
| C2 | **100%** |
| C1+C2 | 75% |

**Finding:** the permission layer stops unauthorized *actions* (leak → 0%) but is
useless against corrupted *conclusions* (suppression → 100%, same as baseline).
Different threats need different defences; conclusion-level injection is the open problem.

## Layout
data/ synthetic SOC: logs, incidents, alerts, payload corpora
soc/ types, datastore, tools, permission layer, ReAct assistant, LLM backend
test_boundary.py permission boundary proven with no model
run_benign.py benign triage gate
run_eval.py leak experiment harness
run_eval_suppress.py suppression experiment harness
demo_hijack.py C0-vs-C2 hijack demo


## Run
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
echo "GROQ_API_KEY=your_key" > .env
python test_boundary.py      # boundary proof (no model)
python run_eval.py           # leak experiment
python run_eval_suppress.py  # suppression experiment
```

## Limitations & future work
Small hand-written corpora; single model. A realistic Splunk + Hydra pipeline is
implemented (see below); Snort IDS detection, a larger corpus, multi-model
evaluation, and a gated state-changing dismissal action remain future work.

## Working application (framework agent + approvals)
Beyond the research harness, the prototype is growing into a working app:
- **Framework agent** (`soc/agent.py`): a LangGraph `StateGraph` whose single tool
  node routes **every** proposed call through the same policy gateway — the framework
  has no bypass path. It produces a structured assessment and validates cited
  evidence ids against what it actually retrieved.
- **Config-driven policy** (`policy.yaml`, `soc/policy.py`): three outcomes —
  ALLOW, DENY, REQUIRE_APPROVAL — validated at load; default deny; every decision
  records its rule and reason.
- **Durable state + approvals** (`soc/state.py`, SQLite): incidents (with a
  version), investigations, evidence refs, proposed actions, approvals, and audit.
  `propose_incident_update` adds comments/escalation immediately but **closure
  requires human approval**. An approval is bound to the exact immutable action and
  the incident version it was proposed against; approval-consumption and the
  incident update are a single atomic transaction, so an approved action executes
  **exactly once**, never after reject/expiry/version-change, and **pending
  approvals survive a restart**. (Local analyst identity is fixed for the demo —
  not production authentication.)

```bash
python demo_approval.py        # closure: reject keeps it open; approve executes once
python scripts/reset_demo.py   # reset ONLY the fictional demo state (soc.db)
python tests/test_state_approvals.py   # 12 deterministic approval tests
```

### Analyst console (local web UI)
A minimal Flask console to review investigations and approve/reject proposals:
```bash
python scripts/seed_ui_demo.py   # populate a reviewable pending approval (no model)
python app.py                    # http://127.0.0.1:5000/  (binds to localhost)
```
It shows the incident list, each investigation's original evidence and structured
assessment, the agent's tool requests with the policy decision for each, and
Approve/Reject controls. Untrusted text is autoescaped; state-changing routes are
CSRF-protected; the analyst identity is a fixed local demo identity (not production
auth). Tests: `python tests/test_ui.py`.

### Enrichment (VirusTotal, optional)
A file-related alert can be enriched with a file-hash reputation lookup:
```bash
python demo_virustotal.py        # offline mock by default
# live:  set SOC_VT_MODE=live and VT_API_KEY, then run the same command
```
Hashes are validated before lookup, credentials stay server-side, files are never
uploaded, and API failures return a structured error. The offline mock labels every
result `source=offline-mock`. The lookup is a gated tool like any other.

## Reliability notes
- Splunk queries are **bounded** (explicit time window + `head` cap) and
  **tenant-scoped at the source**; the tenant id is validated against an allowlist
  before it is placed in SPL.
- An unknown `alert_id` returns `unknown_alert`, never a silent fall-back to all logs.
- Ingested dataset/real-SSH events preserve the original line, carry the source
  timestamp separately from the replay timestamp, and use per-run unique ids.
- TLS is **verified by default**; set `SPLUNK_CA_CERT` (self-signed local cert) or
  `SPLUNK_VERIFY_TLS=0` for an explicit local-lab exception.
- Deterministic offline regression tests: `python tests/test_baseline.py`.

## Realistic evidence source (Splunk)
The log store is pluggable. By default logs come from `data/logs.json`; with
`SOC_LOG_BACKEND=splunk` the assistant queries a local Splunk instance over its
REST API instead. Setup: run Splunk in Docker, create the `soc_logs` index and a
HEC token, ingest with `scripts/ingest_splunk.py`, set the SPLUNK_* vars in `.env`,
then e.g. `SOC_LOG_BACKEND=splunk python run_benign.py`.

## Real attack pipeline (Hydra → sshd → Splunk → assistant)
A genuine brute-force is generated with Hydra against a live sshd; the OS logs it;
`scripts/ingest_real_ssh.py` parses the real sshd lines into events and ships them
to Splunk; then `SOC_LOG_BACKEND=splunk python demo_real_attack.py` has the
assistant read the evidence live from Splunk and correctly classify it as a
true-positive brute-force. (Snort IDS-based detection is the remaining future step.)
