#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path
DIGEST=re.compile(r"^[0-9a-f]{64}$")
def fail(s): raise SystemExit(s)
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def file(root,rel):
 p=(root/rel).resolve()
 try:p.relative_to(root.resolve())
 except ValueError:fail("path escapes indirect-control root")
 if p.is_symlink() or not p.is_file():fail("missing indirect-control evidence: "+rel)
 return p
def main():
 ap=argparse.ArgumentParser();ap.add_argument("root",type=Path);ap.add_argument("--tier",required=True);ap.add_argument("--unit",required=True);a=ap.parse_args();r=a.root.resolve();p=r/a.unit
 d=json.loads(file(r,f"{a.unit}/jump-table-behavior.json").read_text())
 if d.get("schemaVersion")!=1 or d.get("unitId")!=a.unit or d.get("selectedFunction","").startswith("dynsym:") is False:fail("jump-table identity invalid")
 for rel,key in [("source-image.bin","sourceSha256"),("protected-image.bin","protectedSha256"),("native-image.bin","nativeSha256")]:
  if not DIGEST.fullmatch(d.get(key,"")) or digest(file(p,rel))!=d[key]:fail("jump-table hash mismatch")
 if d.get("baselineStatus")!=91 or d.get("transformedStatus")!=91 or not d.get("statusEqual"):fail("jump-table behavior differs")
 if d.get("jumpTableEditCount",0)<1 or d.get("addressMapBindings",0)<1 or d.get("targetResolutionMode")!="bounded-relative-table":fail("jump-table rewrite evidence is incomplete")
 # Require the *actual* producer diagnostic, not a self-declared success
 # field in negative-result.json. Any unrelated failure must fail closed.
 actual=json.loads(file(r,"negative-malformed-table/producer.stdout").read_text())
 observed=json.loads(file(r,"negative-malformed-table/stage.json").read_text())
 if (actual.get("success") is not False or actual.get("stage")!=observed
     or observed.get("status")!="failed"
     or observed.get("firstFailureStage")!="protected-image-producer"
     or observed.get("publicationComplete") is not False
     or observed.get("unitId")!=a.unit+".negative"
     or observed.get("sourceSha256")!=digest(file(r,"negative-malformed-table/source-image.bin"))
     or not any(isinstance(d,dict) and d.get("severity")=="Error"
                and d.get("code")=="IndirectTargetUnresolved"
                for d in observed.get("diagnostics",[]))):
  fail("negative producer failed for an unrelated reason or diagnostic is unverified")
 n=json.loads(file(r,"negative-malformed-table/negative-result.json").read_text())
 if n.get("status")!="passed" or n.get("producerExitStatus")==0 or n.get("expectedDiagnosticFamily")!="IndirectTargetUnresolved" or n.get("protectedImagePublished") or n.get("nativeImagePublished") or n.get("loaderInvoked"):fail("jump-table negative published output or diagnostic claim mismatch")
 entries={}
 for line in file(r,"SHA256SUMS").read_text().splitlines():
  h,rel=line.split("  ",1)
  if not DIGEST.fullmatch(h) or rel in entries or digest(file(r,rel))!=h:fail("indirect-control manifest invalid")
  entries[rel]=h
 actual={x.relative_to(r).as_posix() for x in r.rglob("*") if x.is_file() and x.name!="SHA256SUMS"}
 if actual!=set(entries):fail("indirect-control SHA256SUMS is not closed")
 print("Indirect-control evidence valid: transformed jump table and malformed rollback")
if __name__=="__main__":main()
