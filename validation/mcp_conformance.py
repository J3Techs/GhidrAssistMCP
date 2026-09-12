#!/usr/bin/env python3
"""Small read-only MCP HTTP conformance probe (stdlib only)."""
import argparse, json, pathlib, time, urllib.request, urllib.error
from urllib.parse import quote

class Client:
    def __init__(self, endpoint): self.endpoint, self.sid, self.i = endpoint, None, 0
    def call(self, method, params=None):
        self.i += 1; body = {"jsonrpc":"2.0", "id":self.i, "method":method}
        if params is not None: body["params"] = params
        raw = json.dumps(body, ensure_ascii=False).encode(); headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream"}
        if self.sid: headers["Mcp-Session-Id"] = self.sid
        headers["MCP-Protocol-Version"] = "2025-11-25"
        started=time.perf_counter()
        req=urllib.request.Request(self.endpoint, data=raw, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                data=res.read(); self.sid=res.headers.get("Mcp-Session-Id", self.sid); ctype=res.headers.get("Content-Type","")
        except Exception as e: return {"method":method,"ok":False,"error":str(e),"elapsed_ms":(time.perf_counter()-started)*1000,"request_bytes":len(raw),"response_bytes":0}
        parsed=self.parse(data, ctype); obj=next((item for item in parsed if isinstance(item,dict) and item.get("id")==self.i), None)
        nested_error=isinstance(obj,dict) and ("error" in obj or isinstance(obj.get("result"),dict) and obj["result"].get("isError") is True)
        return {"method":method,"ok":isinstance(obj,dict) and not nested_error,"elapsed_ms":(time.perf_counter()-started)*1000,"request_bytes":len(raw),"response_bytes":len(data),"response":obj}
    def notify(self, method, params=None):
        body={"jsonrpc":"2.0","method":method};
        if params is not None: body["params"]=params
        headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream"}
        if self.sid: headers["Mcp-Session-Id"]=self.sid
        headers["MCP-Protocol-Version"]="2025-11-25"
        req=urllib.request.Request(self.endpoint,data=json.dumps(body).encode(),headers=headers,method="POST")
        try:
            with urllib.request.urlopen(req,timeout=30) as res: res.read()
        except Exception as e: return {"ok":False,"error":str(e)}
        return {"ok":True}
    @staticmethod
    def parse(data, ctype):
        text=data.decode("utf-8","replace")
        if "json" in ctype and not "event-stream" in ctype:
            try: return [json.loads(text)]
            except Exception: return []
        out=[]
        for line in text.splitlines():
            if line.startswith("data:"):
                try: out.append(json.loads(line[5:].strip()))
                except Exception: pass
        if not out:
            try: out=[json.loads(text)]
            except Exception: pass
        return out

def structured(response):
    return (response.get("response") or {}).get("result",{}).get("structuredContent",{})

def await_operation(client, initial):
    """Return (result envelope to inspect, optional wait trace) for sync/async tools."""
    body=structured(initial)
    task_id=body.get("task_id") if isinstance(body,dict) else None
    if not task_id:
        return initial, None
    wait=client.call("tools/call",{"name":"wait_task","arguments":
        {"task_id":task_id,"include_result":True,"timeout_ms":30000}})
    wait_body=structured(wait)
    return {"response":{"result":{"structuredContent":wait_body}},"ok":
            wait["ok"] and wait_body.get("wait_outcome")=="terminal"
            and wait_body.get("result_status")=="included"}, wait

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--endpoint",required=True); ap.add_argument("--output",required=True); ap.add_argument("--fixture-ready")
    a=ap.parse_args(); checks=[]; started=time.time(); fixture=None
    if a.fixture_ready:
        p=pathlib.Path(a.fixture_ready).resolve(); roots=[pathlib.Path.cwd().resolve()/"build"/"upgrade-validation", pathlib.Path.cwd().resolve()/"build"]
        try:
            if not any(p.is_relative_to(r) for r in roots): raise ValueError("fixture path outside disposable build roots")
            fixture=json.loads(p.read_text(encoding="utf-8"))
            if fixture.get("endpoint") != a.endpoint: raise ValueError("endpoint differs from fixture ready file")
            checks.append({"name":"fixture_guard","ok":True,"path":str(p)})
        except Exception as e: checks.append({"name":"fixture_guard","ok":False,"error":str(e)})
    c=Client(a.endpoint)
    init=c.call("initialize",{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"mcp-conformance","version":"1"}}); checks.append({"name":"initialize","result":init,"ok":init["ok"]})
    if init["ok"]:
        notification=c.notify("notifications/initialized"); checks.append({"name":"initialized_notification",**notification})
        for name, params in [("tools/list",{}),("tools/call",{"name":"runtime_capabilities","arguments":{"include_programs":False}}),("tools/call",{"name":"list_binaries","arguments":{"limit":8,"offset":0}})]:
            r=c.call(name,params); checks.append({"name":name,"result":r,"ok":r["ok"]})
        tools=next((c["result"].get("response",{}).get("result",{}).get("tools",[]) for c in checks if c["name"]=="tools/list" and c["ok"]),[])
        if any(t.get("name")=="search_functions_by_name" for t in tools):
            probe=c.call("tools/call",{"name":"search_functions_by_name","arguments":{"search_term":"x","limit":1}}); checks.append({"name":"bounded_search","result":probe,"ok":probe["ok"]})
        resource_list=c.call("resources/list",{}); checks.append({"name":"resources/list","result":resource_list,"ok":resource_list["ok"]})
        resources=resource_list.get("response",{}).get("result",{}).get("resources",[]) if resource_list["ok"] else []
        if resources:
            uri=resources[0].get("uri"); rr=c.call("resources/read",{"uri":uri}); checks.append({"name":"resources/read","result":rr,"ok":rr["ok"]})
        if fixture:
            # Fixture-only selector checks use the manifest's exact opaque IDs
            # and names; no production/live program names are guessed.
            fprograms=fixture.get("programs",[])
            fpath=None
            listed=next((x.get("result",{}).get("response",{}).get("result",{}).get("structuredContent",{})
                         for x in checks if x.get("name")=="tools/call"
                         and x.get("result",{}).get("response",{}).get("result",{}).get("structuredContent",{}).get("programs") is not None),{})
            rows=listed.get("programs",[])
            if fprograms and rows:
                fpath=next((row.get("project_path") for row in rows
                            if row.get("program_id")==fprograms[0].get("program_id")),None)
            page2=c.call("tools/call",{"name":"list_binaries","arguments":{"limit":1,"offset":1}})
            checks.append({"name":"fixture_discovery_page2","result":page2,"ok":page2["ok"]})
            search_tool=next((t for t in tools if t.get("name")=="search_bytes"),None)
            if search_tool and fprograms:
                expected=fprograms[0].get("program_id")
                def selector_probe(check_name, selector, expected_id):
                    probe=c.call("tools/call",{"name":"search_bytes","arguments":
                        {"pattern":"00","limit":1,"program_name":selector}})
                    effective, wait=await_operation(c,probe)
                    body=structured(effective)
                    rows=[{"name":check_name,"result":probe,
                            "ok":probe["ok"] and (bool(structured(probe).get("task_id")) or body.get("program_id")==expected_id)}]
                    if wait is not None:
                        rows.append({"name":check_name+"_wait","result":wait,"ok":effective["ok"] and body.get("operation_result",{}).get("program_id")==expected_id})
                    return rows
                checks.extend(selector_probe("fixture_selector_program_name",fprograms[0].get("name"),expected))
                if fpath:
                    checks.extend(selector_probe("fixture_selector_project_path",fpath,expected))
                spaced=next((p for p in fprograms if "space # selector" in p.get("name", "")),None)
                if spaced:
                    checks.extend(selector_probe("fixture_selector_spaced_name",spaced.get("name"),spaced.get("program_id")))
                    encoded=quote(spaced["name"],safe="")
                    encoded_uri="ghidra://program/"+encoded+"/info"
                    encoded_read=c.call("resources/read",{"uri":encoded_uri})
                    checks.append({"name":"fixture_resource_percent_encoded_selector",
                        "result":encoded_read,"ok":encoded_read["ok"]})
                # Verify the documented alias resolves to the same selected
                # program when both selector keys are advertised.
                props=search_tool.get("inputSchema",{}).get("properties",{})
                if "program" in props:
                    alias=c.call("tools/call",{"name":"search_bytes","arguments":
                        {"pattern":"00","limit":1,"program":fprograms[0].get("name")}})
                    alias_body=(alias.get("response") or {}).get("result",{}).get("structuredContent",{})
                    checks.append({"name":"fixture_program_alias_matches_program_name",
                        "result":alias,"ok":alias["ok"] and alias_body.get("program_id")==expected})
            tool_names={t.get("name") for t in tools}
            if {"get_binary_info", "get_program_info"}.issubset(tool_names):
                canonical=c.call("tools/call",{"name":"get_binary_info","arguments":{}})
                alias=c.call("tools/call",{"name":"get_program_info","arguments":{}})
                ctext=json.dumps((canonical.get("response") or {}).get("result",{}),sort_keys=True)
                atext=json.dumps((alias.get("response") or {}).get("result",{}),sort_keys=True)
                checks.append({"name":"fixture_tool_alias_get_program_info",
                    "result":{"canonical":canonical,"alias":alias},
                    "ok":canonical["ok"] and alias["ok"] and ctext==atext})
        missing=c.call("tools/call",{"name":"get_binary_info","arguments":{"program_id":"missing-program-id"}}); checks.append({"name":"missing_selector","result":missing,"ok":not missing["ok"] and "missing-program-id" in json.dumps(missing.get("response",{}))})
        exact=None
        programs=next((c["result"].get("response",{}).get("result",{}).get("structuredContent",{}).get("programs",[]) for c in checks if c["name"]=="tools/call" and c["result"].get("response",{}).get("result",{}).get("structuredContent",{}).get("programs") is not None),[])
        if programs and fixture:
            exact=c.call("tools/call",{"name":"get_code","arguments":{"program_id":programs[0]["program_id"],"function":"1000","format":"disassembly","max_items":20}})
            checks.append({"name":"exact_get_code","result":exact,"ok":exact["ok"]})
        wait=c.call("tools/call",{"name":"get_task_status","arguments":{"task_id":"missing-task"}}); checks.append({"name":"task_status_error","result":wait,"ok":not wait["ok"] and isinstance(wait.get("response",{}).get("result"),dict) and wait["response"]["result"].get("isError") is True})
    report={"schema_version":1,"source":"validation/mcp_conformance.py","fixture":fixture is not None,"endpoint":a.endpoint,"started_at":started,"checks":checks,"passed":all(x.get("ok",True) for x in checks)}
    out=pathlib.Path(a.output); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); print(json.dumps({"passed":report["passed"],"output":str(out)}))
    return 0 if report["passed"] else 1
if __name__=="__main__": raise SystemExit(main())
