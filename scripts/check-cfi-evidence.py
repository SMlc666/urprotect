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
 except ValueError:fail("path escapes CFI root")
 if p.is_symlink() or not p.is_file():fail("missing CFI evidence file: "+rel)
 return p
def main():
 ap=argparse.ArgumentParser();ap.add_argument("root",type=Path);ap.add_argument("--tier",required=True);ap.add_argument("--runtime",required=True);ap.add_argument("--unit",required=True);a=ap.parse_args();r=a.root.resolve()
 positive= r/a.unit
 d=json.loads(file(r,"positive/"+a.unit+"/cfi-behavior.json").read_text())
 if d.get("schemaVersion")!=1 or d.get("unitId")!=a.unit:fail("CFI identity mismatch")
 for rel,key in [(f"positive/{a.unit}/source-image.bin","sourceImageSha256"),(f"positive/{a.unit}/protected-image.bin","protectedImageSha256"),(f"positive/{a.unit}/native-image.bin","nativeImageSha256")]:
  if not isinstance(d.get(key),str) or not DIGEST.fullmatch(d[key]) or digest(file(r,rel))!=d[key]:fail("CFI hash mismatch: "+key)
 b,t=d.get("baseline"),d.get("transformed")
 if not isinstance(b,dict) or not isinstance(t,dict) or not d.get("frameCountEqual") or not d.get("entryStatusEqual") or not d.get("releaseStatusEqual") or not d.get("transformedFrameObserved"):fail("CFI behavior mismatch")
 if b.get("transformedImage")!=0 or t.get("transformedImage")!=1 or b.get("transformedFrameObserved")!=0 or t.get("transformedFrameObserved")!=1:fail("CFI harness flags invalid")
 # Require the *actual* producer diagnostic, not a self-declared success
 # field in negative-result.json. Any unrelated failure must fail closed.
 actual=json.loads(file(r,"negative-malformed-eh-frame/producer.stdout").read_text())
 observed=json.loads(file(r,"negative-malformed-eh-frame/stage.json").read_text())
 if (actual.get("success") is not False or actual.get("stage")!=observed
     or observed.get("status")!="failed"
     or observed.get("firstFailureStage")!="protected-image-producer"
     or observed.get("publicationComplete") is not False
     or observed.get("unitId")!=a.unit+".negative"
     or observed.get("sourceSha256")!=digest(file(r,"negative-malformed-eh-frame/source-image.bin"))
     or not any(isinstance(d,dict) and d.get("severity")=="Error"
                and d.get("code")=="UnwindMetadataMalformed"
                for d in observed.get("diagnostics",[]))):
  fail("negative producer failed for an unrelated reason or diagnostic is unverified")
 n=json.loads(file(r,"negative-malformed-eh-frame/negative-result.json").read_text())
 if n.get("status")!="passed" or n.get("producerExitStatus")==0 or n.get("nativeImagePublished") or n.get("protectedImagePublished") or n.get("loaderInvoked") or n.get("expectedDiagnosticFamily")!="UnwindMetadataMalformed":fail("CFI negative invalid")
 entries={}
 for line in file(r,"SHA256SUMS").read_text().splitlines():
  h,rel=line.split("  ",1)
  if not DIGEST.fullmatch(h) or rel in entries or digest(file(r,rel))!=h:fail("CFI manifest invalid")
  entries[rel]=h
 actual={p.relative_to(r).as_posix() for p in r.rglob("*") if p.is_file() and p.name!="SHA256SUMS"}
 if actual!=set(entries):fail("CFI manifest not closed")
 print("CFI evidence valid: transformed unwind and malformed rollback")
if __name__=="__main__":main()
