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
Small hand-written corpora; single model; synthetic data. Future: a realistic
Splunk/Hydra/Snort pipeline, a larger corpus, multi-model evaluation, and a gated
state-changing dismissal action.
