#!/usr/bin/env python3
"""Validate the stable AArch64 runtime covering-set registry."""
import json
import sys
from pathlib import Path

TIERS = {"pr", "nightly", "release"}
EXPECTED = {"glibc.current.native-arm64", "glibc.older.ubuntu-22.04-arm64", "musl.1.2.4.ubuntu-native", "musl.1.2.5.alpine-3.22.2", "bionic.termux.locked", "kernel-page.16k.native-aarch64"}
HIGH_RISK = {"glibc-older x PT_LOAD.p_align=16384", "musl-1.2.5 x PT_LOAD.p_align=16384"}
def fail(message): raise SystemExit(f"runtime matrix: {message}")
def validate(data):
    if not isinstance(data, dict) or type(data.get("schemaVersion")) is not int or data["schemaVersion"] != 1: fail("schemaVersion must be integer 1")
    cells=data.get("cells")
    if not isinstance(cells,list) or any(not isinstance(c,dict) for c in cells) or len(cells)!=len(EXPECTED): fail("cells must contain the reviewed covering set exactly, without duplicates")
    ids=[c.get("id") for c in cells]
    if any(not isinstance(cid,str) for cid in ids) or len(set(ids))!=len(ids) or set(ids)!=EXPECTED: fail("cells must contain the reviewed covering set exactly, without duplicates")
    if not isinstance(data.get("selection"),str) or not data["selection"].strip(): fail("selection rationale is required")
    tiers=data.get("tiers")
    if not isinstance(tiers,dict) or set(tiers)!=TIERS: fail("tiers must define pr, nightly, release exactly")
    if any(not isinstance(items,list) or any(not isinstance(item,str) for item in items) for items in tiers.values()): fail("tier selections must be arrays of cell ID strings")
    by_id={c["id"]:c for c in cells}
    for tier,selected in tiers.items():
        declared={c["id"] for c in cells if tier in c.get("tier",[])}
        if not isinstance(selected,list) or len(selected)!=len(set(selected)) or set(selected)!=declared: fail(f"{tier} selection must match cell tier declarations")
    for c in cells:
        cid=c["id"]
        for f in ("runtime","version","platform","kernel","pageSize","rationale","producerClass"):
            if not isinstance(c.get(f),str) or not c[f].strip(): fail(f"{cid}.{f} is required")
        if not isinstance(c.get("tier"),list) or not c["tier"] or any(not isinstance(t,str) or t not in TIERS for t in c["tier"]): fail(f"{cid}.tier must contain known tier names")
        if type(c.get("required")) is not bool: fail(f"{cid}.required must be boolean")
        interactions=c.get("interactions",[])
        if not isinstance(interactions,list) or any(not isinstance(item,str) or not item.strip() for item in interactions): fail(f"{cid}.interactions must be an array of names")
        features=c.get("fixtureFeatures")
        if not isinstance(features,str) or not features.strip(): fail(f"{cid}.fixtureFeatures must document the ELF/runtime shape")
        if cid!="kernel-page.16k.native-aarch64" and c["required"] is not True: fail(f"{cid} is a required runtime evidence cell")
        if c["platform"] in {"arm64-container","native-arm64-container"} and cid!="bionic.termux.locked" and not (isinstance(c.get("imageDigest"),str) and c["imageDigest"].startswith("sha256:") and len(c["imageDigest"])==71): fail(f"{cid} requires an immutable OCI digest")
        if cid=="bionic.termux.locked" and c.get("imageDigest")!="fixtures/manifest.json": fail("bionic cell must point at the existing locked fixture registry")
    page=by_id["kernel-page.16k.native-aarch64"]
    if page["runtime"]!="kernel-page-probe" or page.get("probeRequired") is not True or type(page.get("claimRequired")) is not bool: fail("16KiB cell must separate mandatory probe from runtime claim")
    if page.get("claimRequired") is not False or page["required"] is not False: fail("16KiB runtime claim remains optional until native environment support exists")
    if by_id["glibc.current.native-arm64"].get("version")!="2.39": fail("current native Ubuntu 24.04 glibc cell must pin version 2.39")
    for cid in ("glibc.older.ubuntu-22.04-arm64","musl.1.2.5.alpine-3.22.2"):
        interactions=set(by_id[cid].get("interactions",[]))
        if len(interactions)!=len(by_id[cid].get("interactions",[])) or not interactions: fail(f"{cid} must declare named high-risk interaction")
    if not HIGH_RISK.issubset(set(sum((c.get("interactions",[]) for c in cells),[]))): fail("older-glibc/musl-1.2.5 x 16KiB PT_LOAD interactions are required")
    b=by_id["bionic.termux.locked"]
    artifacts=b.get("requiredArtifacts")
    if b.get("evidenceProducer")!="bionic-native-arm64" or not isinstance(artifacts,list) or not artifacts: fail("bionic cell must consume its required native producer evidence")
    if any(not isinstance(path,str) or not path or path.startswith("/") or ".." in Path(path).parts for path in artifacts) or len(artifacts)!=len(set(artifacts)): fail("bionic cell evidence paths must be unique safe relative paths")
    if any(t not in b.get("tier",[]) for t in TIERS): fail("bionic producer must be selected in every tier")
if __name__=="__main__":
    try: validate(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
    except (OSError,json.JSONDecodeError,IndexError) as exc: fail(str(exc))
    print("runtime matrix valid: six named AArch64 cells and reviewed interactions")
