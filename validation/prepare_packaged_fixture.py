#!/usr/bin/env python3
"""Prepare an owned fixture using packaged runtime/dependencies; never install globally."""
import argparse, pathlib, zipfile

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--archive',required=True); ap.add_argument('--output-dir',required=True)
    a=ap.parse_args(); root=pathlib.Path(__file__).resolve().parents[1]; dest=pathlib.Path(a.output_dir).resolve()
    if not dest.is_relative_to(root/'build') or dest.exists(): raise ValueError('Use a fresh directory under this repository build/')
    dest.mkdir(parents=True)
    with zipfile.ZipFile(a.archive) as z:
        for name in z.namelist():
            if not (dest/name).resolve().is_relative_to(dest): raise ValueError('Unsafe archive path')
        z.extractall(dest)
    args=(root/'build/upgrade-fixture-java.args').read_text().splitlines()
    index=args.index('-classpath')+1
    original=args[index].strip('"').split(';')
    keep=[p for p in original if '/Ghidra/' in p or p.endswith('/classes/java/test') or p.endswith('/resources/test')]
    jars=sorted(dest.glob('**/lib/*.jar'))
    if len([p for p in jars if p.name=='GhidrAssistMCP.jar']) != 1: raise ValueError('Missing runtime JAR')
    args[index]='"'+';'.join([str(p).replace('\\','/') for p in jars]+keep)+'"'
    result=dest/'java.args'; result.write_text('\n'.join(args)+'\n',encoding='utf-8'); print(result)
if __name__=='__main__': main()
