#!/usr/bin/env python3
"""Read-only decompiler timing on an explicitly identified disposable fixture."""
import argparse, json, pathlib, statistics
from mcp_conformance import Client

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--fixture-ready', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--warm', type=int, choices=range(1, 21), default=7)
    a = ap.parse_args()
    ready = json.loads(pathlib.Path(a.fixture_ready).read_text())
    pid = next(p['program_id'] for p in ready['programs'] if p['name'] == 'source')
    c = Client(ready['endpoint'])
    init = c.call('initialize', {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'read-benchmark','version':'2'}})
    if not init['ok']: raise RuntimeError(init)
    if not c.notify('notifications/initialized')['ok']: raise RuntimeError('initialization notification failed')
    samples, calls = [], []
    for phase, max_chars in [('first_observed', 200000)] + [('warm', 200000)] * a.warm + [('bounded_1024', 1024)]:
        r = c.call('tools/call', {'name':'get_code','arguments':{'program_id':pid,'function':'1000','format':'decompiler','structured':True,'max_items':20,'max_chars':max_chars}})
        calls.append(r)
        elapsed, response_bytes = r['elapsed_ms'], r['response_bytes']
        operation = (r.get('response') or {}).get('result', {})
        task_id = operation.get('structuredContent', {}).get('task_id')
        if task_id:
            w = c.call('tools/call', {'name':'wait_task','arguments':{'task_id':task_id,'timeout_ms':30000,'include_result':True}})
            calls.append(w); elapsed += w['elapsed_ms']; response_bytes += w['response_bytes']
            operation = (w.get('response') or {}).get('result', {}).get('structuredContent', {}).get('operation_result', {})
        sc = operation.get('structuredContent', {})
        complete = bool(sc.get('decompile_completed') and sc.get('c')) and not operation.get('isError', False)
        samples.append({'phase':phase,'elapsed_ms':elapsed,'response_bytes':response_bytes,'task_waited':bool(task_id),'complete':complete,'c_chars':len(sc.get('c',''))})
    report = {'schema_version':2,'endpoint':ready['endpoint'],'program_id':pid,'build_info':ready.get('build_info'),'samples':samples,'calls':calls,
              'summary':{'first_observed_ms':samples[0]['elapsed_ms'],'warm_median_ms':statistics.median(s['elapsed_ms'] for s in samples if s['phase']=='warm'),
                         'all_completed':all(s['complete'] for s in samples),'total_response_bytes':sum(s['response_bytes'] for s in samples),
                         'cold_claim':False,'notes':'First observed is cold only if independently proven no earlier decompile in this process.'}}
    out = pathlib.Path(a.output); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report['summary']))
    return 0 if report['summary']['all_completed'] else 1
if __name__ == '__main__': raise SystemExit(main())
