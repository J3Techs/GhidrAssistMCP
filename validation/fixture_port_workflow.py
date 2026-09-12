#!/usr/bin/env python3
"""Mutating PORT smoke, restricted to a fresh UpgradeFixtureServer project under build/."""
import argparse, json, pathlib
from mcp_conformance import Client

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--fixture-ready',required=True); ap.add_argument('--output',required=True)
    a=ap.parse_args(); root=pathlib.Path(__file__).resolve().parents[1]; ready=json.loads(pathlib.Path(a.fixture_ready).read_text())
    project=pathlib.Path(ready['project_directory']).resolve()
    if not project.is_relative_to(root/'build/upgrade-validation') or not project.name.startswith('project-'):
        raise ValueError('Only an owned disposable upgrade fixture is permitted')
    c=Client(ready['endpoint']); traces=[]
    def call(name, args):
        response=c.call('tools/call',{'name':name,'arguments':args}); traces.append({'tool':name,'arguments':args,**response})
        if not response['ok']: raise RuntimeError(str(response))
        result=response['response']['result']; body=result.get('structuredContent',{})
        if body.get('task_id'):
            wait=c.call('tools/call',{'name':'wait_task','arguments':{'task_id':body['task_id'],'timeout_ms':30000,'include_result':True}})
            traces.append({'tool':'wait_task',**wait})
            if not wait['ok']: raise RuntimeError(str(wait))
            result=wait['response']['result'].get('structuredContent',{}).get('operation_result')
            if not result or result.get('isError'): raise RuntimeError(str(wait))
            body=result.get('structuredContent',{})
        return body
    report={'fixture':ready,'passed':False,'traces':traces,'closure_scope':'MCP consumer reacquisition; true disk reopen is covered by native persistence tests'}
    try:
        init=c.call('initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'fixture-port-validation','version':'1'}})
        if not init['ok'] or not c.notify('notifications/initialized')['ok']: raise RuntimeError(str(init))
        programs=call('list_binaries',{'limit':8})['programs']
        source=next(p['program_id'] for p in programs if p['name']=='source')
        target=next(p['program_id'] for p in programs if p['name']=='target')
        fp=call('port_ledger',{'action':'get','program_id':source,'address':'1000'})['current_fingerprint']
        operation='packaged-port-validation-v1'
        row={'target_addr':'1000','name':'answer_port','prototype':'int answer_port(void)',
             'port_metadata':{'operation_id':operation,'source_program_id':source,'source_address':'1000','source_fingerprint':fp,'method':'disposable identical-byte fixture'}}
        args={'target_program':target,'transfers':[row],'dry_run':True}
        preview=call('bulk_transfer_labels',args)
        apply=call('bulk_transfer_labels',{**args,'dry_run':False,'preview_token':preview['preview_token']})
        initial=call('port_ledger',{'action':'get','program_id':target,'address':'1000'})
        assert initial['ledger']['verification']=='applied_unverified', initial
        verified=call('port_ledger',{'action':'verify','program_id':target,'address':'1000','operation_id':operation,'expected_target_revision':initial['modification_number']})
        assert verified['verified'] is True, verified
        saved=call('save_program',{'program_id':target})
        target=next(p['program_id'] for p in call('list_binaries',{'limit':8})['programs'] if p['name']=='target')
        closed=call('close_program',{'name':target})
        call('open_program',{'action':'open','name':'/target'})
        target=next(p['program_id'] for p in call('list_binaries',{'limit':8})['programs'] if p['name']=='target')
        resumed=call('port_ledger',{'action':'get','program_id':target,'address':'1000'})
        assert resumed['ledger']['verification']=='verified' and resumed['checkpoint_matches'], resumed
        assert call('port_ledger',{'action':'get','program_id':source,'address':'1000'})['current_fingerprint']==fp
        report.update(passed=True,preview=preview,apply=apply,save=saved,close=closed,resumed=resumed)
    except Exception as e: report['error']=str(e)
    out=pathlib.Path(a.output); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,indent=2))
    print(json.dumps({'passed':report['passed'],'error':report.get('error'),'output':str(out)}))
    return 0 if report['passed'] else 1
if __name__=='__main__': raise SystemExit(main())
