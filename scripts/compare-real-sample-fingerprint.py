#!/usr/bin/env python3
"""Compare CI-generated ELF facts with the locked registry invariants."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

class ComparisonError(Exception): pass

def load(path: Path):
    try: return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as e: raise ComparisonError(f'could not read {path}: {e}') from e

def normal(field, value):
    if field == 'data':
        value = str(value).lower()
        return 'little-endian' if 'little' in value else value
    if field == 'type':
        value = str(value).split(' ', 1)[0].upper()
        return {
            'DYN': 'ET_DYN',
            'ET_DYN': 'ET_DYN',
            'EXEC': 'ET_EXEC',
            'ET_EXEC': 'ET_EXEC',
        }.get(value, value)
    if field == 'machine':
        return 'AArch64' if 'aarch64' in str(value).lower() or 'arm64' in str(value).lower() else str(value)
    return value

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', required=True, type=Path)
    p.add_argument('--project-id', required=True)
    p.add_argument('--fingerprint', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a=p.parse_args()
    try:
        manifest=load(a.manifest); projects=manifest['corpus']['projects']
        project=next((x for x in projects if x.get('projectId') == a.project_id), None)
        if not isinstance(project, dict): raise ComparisonError(f'project not found: {a.project_id}')
        policy=project.get('fingerprintPolicy'); expected=project.get('featureFingerprint')
        actual=load(a.fingerprint)
        if not isinstance(policy, dict) or policy.get('mode') != 'ci-discovery-lock': raise ComparisonError('registry fingerprintPolicy must be ci-discovery-lock')
        if not isinstance(expected, dict) or not isinstance(actual, dict): raise ComparisonError('fingerprint roots must be objects')
        fields=policy.get('compare', ['elfClass','data','machine','type','interpreter'])
        mismatches=[]; observed={}
        for field in fields:
            exp=expected.get(field); got=actual.get(field)
            observed[field]=got
            if normal(field, got) != normal(field, exp): mismatches.append({'field':field,'expected':exp,'actual':got})
        expected_tags=expected.get('expectedFeatureTags', [])
        actual_tags=actual.get('featureTags', [])
        comparison={'schemaVersion':1,'projectId':a.project_id,'mode':policy['mode'],'status':'passed' if not mismatches else 'failed','comparedFields':observed,'mismatches':mismatches,'expectedFeatureTags':expected_tags,'observedFeatureTags':actual_tags,'featureTagPolicy':'record-only'}
        a.output.parent.mkdir(parents=True, exist_ok=True); a.output.write_text(json.dumps(comparison,indent=2,sort_keys=True)+'\n')
    except (ComparisonError, KeyError, TypeError) as e:
        print(f'FAIL fingerprint comparison: {e}',file=sys.stderr); return 1
    if mismatches:
        print(f'FAIL fingerprint comparison: {a.project_id}: {mismatches}',file=sys.stderr); return 1
    print(f'PASS fingerprint comparison: {a.project_id}')
    return 0
if __name__ == '__main__': raise SystemExit(main())
