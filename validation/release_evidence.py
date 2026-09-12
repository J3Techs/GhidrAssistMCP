#!/usr/bin/env python3
"""Record release artifact identity and verifiable fixture evidence; never installs/restarts."""
import argparse, hashlib, io, json, pathlib, subprocess, zipfile, xml.etree.ElementTree as ET

def digest(data): return hashlib.sha256(data).hexdigest()
def git_output(root, *args):
    try:
        return subprocess.check_output(['git', *args], cwd=root, text=True, stderr=subprocess.PIPE).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--archive',required=True); ap.add_argument('--output',required=True)
    args=ap.parse_args(); root=pathlib.Path(__file__).resolve().parents[1]; archive=pathlib.Path(args.archive).resolve()
    inputs=sorted([*root.glob('src/main/**/*'),root/'build.gradle',root/'extension.properties'],key=lambda p:p.relative_to(root).as_posix())
    inputs=[p for p in inputs if p.is_file()]; source_hash=hashlib.sha256(); manifest=[]
    for p in inputs:
        name=p.relative_to(root).as_posix(); data=p.read_bytes(); source_hash.update(name.encode()+b'\0'+data+b'\0')
        manifest.append({'path':name,'bytes':len(data),'sha256':digest(data)})
    tests={'tests':0,'failures':0,'errors':0,'skipped':0}; suites=[]
    for p in sorted(root.glob('build/test-results/test/TEST-*.xml')):
        suite=ET.parse(p).getroot(); counts={k:int(suite.get(k,'0')) for k in tests}
        for k,v in counts.items():tests[k]+=v
        suites.append({'suite':suite.get('name'),**counts,'sha256':digest(p.read_bytes())})
    guide=(root/'src/main/resources/ghidrassistmcp/operating-guide.md').read_bytes()
    with zipfile.ZipFile(archive) as z:
        names=z.namelist()
        forbidden_roots={'claude-code-integration','grok-integration','codex-integration','.claude-plugin','.agents','validation','build','docs'}
        extension_root = next((pathlib.PurePosixPath(n).parts[0] for n in names
                               if n.endswith('/lib/GhidrAssistMCP.jar')), None)
        forbidden=[]
        for n in names:
            parts=pathlib.PurePosixPath(n).parts
            relative=parts[1:] if extension_root and parts and parts[0] == extension_root else parts
            if relative and (relative[0] in forbidden_roots or relative[0] == 'CLAUDE.md'): forbidden.append(n)
        empty_entries=[n for n in names if n.endswith('/') and
                       not any(child.startswith(n) and not child.endswith('/') for child in names)]
        jars=[n for n in names if n.endswith('/lib/GhidrAssistMCP.jar')]
        if len(jars)!=1: raise ValueError('Expected one runtime JAR')
        jar=z.read(jars[0]); dependencies=[{'path':n,'sha256':digest(z.read(n))} for n in names if n.endswith('.jar')]
        with zipfile.ZipFile(io.BytesIO(jar)) as j:
            packaged_guide=j.read('ghidrassistmcp/operating-guide.md')
            properties=j.read('build-info.properties').decode('latin1')
            cls=j.read('ghidrassistmcp/GhidrAssistMCPBackend.class'); major=int.from_bytes(cls[6:8],'big')
    source_sha256=source_hash.hexdigest()
    revision=git_output(root,'rev-parse','HEAD')
    source_status=git_output(root,'status','--porcelain','--','src/main','build.gradle','extension.properties')
    toolchain={k: next((line.split('=',1)[1] for line in properties.splitlines() if line.startswith(k+'=')), 'unknown')
               for k in ['java_version','gradle_version','ghidra_version']}
    build_properties=dict(line.split('=',1) for line in properties.splitlines() if '=' in line)
    provenance_ok=(build_properties.get('source_sha256') == source_sha256)
    if revision is not None:
        provenance_ok = provenance_ok and build_properties.get('revision') == revision
    if source_status is not None:
        provenance_ok = provenance_ok and build_properties.get('dirty') == str(bool(source_status)).lower()
    report={'schema_version':1,'validation_level':'source-and-packaged-fixtures','installed_runtime_verified':False,
        'head':revision or 'unknown','revision_known':revision is not None,
        'source_dirty':('unknown' if source_status is None else bool(source_status)),
        'source_inputs':['src/main/**','build.gradle','extension.properties'],'toolchain':toolchain,
        'archive':str(archive),'archive_sha256':digest(archive.read_bytes()),'runtime_jar_sha256':digest(jar),
        'source_sha256':source_sha256,'source_manifest':manifest,'dependencies':dependencies,
        'build_properties':properties,'java_class_major':major,'packaged_guide_matches':guide==packaged_guide,
        'forbidden_archive_paths':forbidden,'empty_archive_entries':empty_entries,'tests':tests,'test_suites':suites}
    report['artifact_checks_passed']=not forbidden and not empty_entries
    report['artifact_checks_passed'] = report['artifact_checks_passed'] and guide==packaged_guide and major==65 and provenance_ok
    destination=pathlib.Path(args.output);destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['archive_sha256','source_sha256','artifact_checks_passed','tests']}))
    return 0 if report['artifact_checks_passed'] and tests['tests'] and not tests['failures'] and not tests['errors'] else 1
if __name__=='__main__':raise SystemExit(main())
