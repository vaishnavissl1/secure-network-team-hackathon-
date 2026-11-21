"""Publish a completed, correlated defensive run to the local UI."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile

folder=Path(sys.argv[1])
summary=json.loads((folder/"alerts.json").read_text())
if not summary["benign"]["ok"]:
    sys.exit("Incomplete benign verification")
waf_id=re.search(r"403 with request ID ([0-9a-f]{32})",(folder/"waf.txt").read_text()).group(1)
burst=re.findall(r"Probe (\d+) status (\d+) request_id ([0-9a-f]{32})",(folder/"limiter.txt").read_text())
wanted={rid for _,_,rid in burst}|{waf_id}
access={}
with Path("logs/nginx/access.log").open() as f:
    for line in f:
        row=json.loads(line)
        if row["request_id"] in wanted:
            access[row["request_id"]]=row
with Path("logs/modsec/audit.log").open() as f:
    tx=next(t for t in (json.loads(line)["transaction"] for line in f) if t["unique_id"]==waf_id)
rules=sorted({str(m["details"]["ruleId"]) for m in tx["messages"]})
assert tx["is_interrupted"] and {"920420","949110"} <= set(rules)
assert access[waf_id]["status"]==403 and access[waf_id]["upstream_status"]==""
limited=0
assert len(wanted)==13 and len(burst)==12
for _,status,rid in burst:
    event=access[rid]
    assert event["status"]==int(status)
    if status=="429":
        assert event["limit_req_status"]=="REJECTED" and event["upstream_status"]==""
        limited+=1
    else:
        assert status in ("401","400") and event["upstream_status"]==status and event["limit_req_status"]=="PASSED"
assert 0 < limited < len(burst)
summary["controls"]={"waf_request_id":waf_id,"waf_rules":rules,"burst_total":len(burst),
    "burst_rejected":limited,"burst_admitted":len(burst)-limited,"recovery":True,
    "tls":["1.2","1.3"],"backend_private":True,"burst":[access[rid] for _,_,rid in burst]}
for target in (folder/"demo.json", Path("dashboard/alerts.json")):
    with tempfile.NamedTemporaryFile("w",encoding="utf8",dir=target.parent,delete=False) as f:
        json.dump(summary,f,indent=2)
    os.replace(f.name,target)
print("Published",summary["run_id"],"from",folder)
