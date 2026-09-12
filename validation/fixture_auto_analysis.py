#!/usr/bin/env python3
"""Exercise native auto-analysis over MCP against an owned disposable fixture."""
import argparse
import json
import pathlib
import time

from mcp_conformance import Client, structured


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture-ready', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    build = pathlib.Path(__file__).resolve().parents[1] / 'build'
    manifest = pathlib.Path(args.fixture_ready).resolve()
    if not manifest.is_relative_to(build.resolve()):
        raise ValueError('Use a disposable fixture manifest under build/')
    fixture = json.loads(manifest.read_text(encoding='utf-8'))
    project = pathlib.Path(fixture['project_directory']).resolve()
    if not project.is_relative_to(build.resolve()):
        raise ValueError('Fixture project must be under build/')
    client = Client(fixture['endpoint'])
    checks = []

    def call(name, arguments):
        response = client.call('tools/call', {'name': name, 'arguments': arguments})
        if not response['ok']:
            raise RuntimeError(response)
        result = response['response']['result']
        task_id = structured(response).get('task_id')
        deadline = time.monotonic() + 120
        while task_id:
            if time.monotonic() > deadline:
                raise TimeoutError('Fixture analysis did not complete; task may still run')
            wait = client.call('tools/call', {'name': 'wait_task', 'arguments': {
                'task_id': task_id, 'timeout_ms': 10000, 'include_result': True}})
            if not wait['ok']:
                raise RuntimeError(wait)
            body = structured(wait)
            if body.get('wait_outcome') != 'terminal':
                continue
            result = body.get('operation_result')
            if not isinstance(result, dict) or result.get('isError'):
                raise RuntimeError(body)
            break
        checks.append({'tool': name, 'arguments': arguments, 'result': result})
        return result

    try:
        initialized = client.call('initialize', {'protocolVersion': '2025-11-25',
            'capabilities': {}, 'clientInfo': {'name': 'fixture-auto-analysis', 'version': '1'}})
        if not initialized['ok']:
            raise RuntimeError(initialized)
        client.notify('notifications/initialized')
        capabilities = call('runtime_capabilities', {'include_programs': False})['structuredContent']
        if not capabilities['headless']:
            raise ValueError('Fixture must be headless')
        # Only names from the fixture generator, never a production program selector.
        source = next(p for p in fixture['programs'] if p['name'] == 'source')
        for mode in ('full', 'changes'):
            call('analyze_program', {'program_id': source['program_id'], 'mode': mode})
        call('save_program', {'program_id': source['program_id']})
        report = {'passed': True, 'checks': checks}
    except Exception as error:
        report = {'passed': False, 'error': str(error), 'checks': checks}
    pathlib.Path(args.output).write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'checks': len(checks), 'error': report.get('error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
