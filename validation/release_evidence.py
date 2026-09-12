#!/usr/bin/env python3
"""Record release artifact identity and verifiable fixture evidence; never installs/restarts."""
import argparse, hashlib, io, json, pathlib, subprocess, zipfile, xml.etree.ElementTree as ET

def digest(data): return hashlib.sha256(data).hexdigest()
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
        names=z.namelist(); forbidden=[n for n in names if any('/'+part+'/' in '/'+n for part in ['claude-code-integration','grok-integration','.claude-plugin','.agents','validation','build'])]
        jars=[n for n in names if n.endswith('/lib/GhidrAssistMCP.jar')]
        if len(jars)!=1: raise ValueError('Expected one runtime JAR')
        jar=z.read(jars[0]); dependencies=[{'path':n,'sha256':digest(z.read(n))} for n in names if n.endswith('.jar')]
        with zipfile.ZipFile(io.BytesIO(jar)) as j:
            packaged_guide=j.read('ghidrassistmcp/operating-guide.md')
            properties=j.read('build-info.properties').decode('latin1')
            cls=j.read('ghidrassistmcp/GhidrAssistMCPBackend.class'); major=int.from_bytes(cls[6:8],'big')
    report={'schema_version':1,'validation_level':'source-and-packaged-fixtures','installed_runtime_verified':False,
        'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'archive':str(archive),'archive_sha256':digest(archive.read_bytes()),'runtime_jar_sha256':digest(jar),
        'source_sha256':source_hash.hexdigest(),'source_manifest':manifest,'dependencies':dependencies,
        'build_properties':properties,'java_class_major':major,'packaged_guide_matches':guide==packaged_guide,
        'forbidden_archive_paths':forbidden,'tests':tests,'test_suites':suites}
    report['artifact_checks_passed']=not forbidden and guide==packaged_guide and major==65 and ('source_sha256='+source_hash.hexdigest()) in properties
    destination=pathlib.Path(args.output);destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['archive_sha256','source_sha256','artifact_checks_passed','tests']}))
    return 0 if report['artifact_checks_passed'] and tests['tests'] and not tests['failures'] and not tests['errors'] else 1
if __name__=='__main__':raise SystemExit(main())
