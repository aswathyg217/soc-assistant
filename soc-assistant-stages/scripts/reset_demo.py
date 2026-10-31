"""Reset ONLY the fictional demo state: delete the local SQLite db and re-seed the
incidents from data/incidents.json. Touches nothing else. Safe to run before any
demo. Usage:  python scripts/reset_demo.py [db_path]"""
import os, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import json
from soc.state import State, seed_from_json

db = sys.argv[1] if len(sys.argv) > 1 else "soc.db"
for f in (db, db + "-wal", db + "-shm"):
    if os.path.exists(f):
        os.remove(f)
incidents = json.loads((pathlib.Path(__file__).resolve().parent.parent / "data" / "incidents.json").read_text())
st = State(db)
seed_from_json(st, incidents)
print(f"Reset demo state in '{db}'. Seeded {len(incidents)} incidents (fictional data only).")
for inc in st.list_incidents():
    print(f"  {inc['id']}  tenant={inc['tenant']}  status={inc['status']}  v{inc['version']}")
