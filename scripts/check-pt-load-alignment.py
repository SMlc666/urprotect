#!/usr/bin/env python3
"""Bounded readelf -lW PT_LOAD p_align checker for controlled fixtures."""
import sys
from pathlib import Path
MAX_BYTES=256*1024
MAX_LINES=4096
MAX_LINE=4096
MAX_LOADS=64
def main():
    if len(sys.argv)!=3: raise SystemExit("usage: check-pt-load-alignment.py READELF_OUTPUT EXPECTED_ALIGN")
    path=Path(sys.argv[1])
    try: expected=int(sys.argv[2],0)
    except ValueError: raise SystemExit("expected alignment must be an integer")
    if expected<=0 or expected&(expected-1): raise SystemExit("expected alignment must be a positive power of two")
    if path.stat().st_size>MAX_BYTES: raise SystemExit("readelf output exceeds 256KiB bound")
    lines=path.read_text(encoding="utf-8",errors="strict").splitlines()
    if len(lines)>MAX_LINES: raise SystemExit("readelf output exceeds line-count bound")
    loads=[]
    for line in lines:
        if len(line)>MAX_LINE: raise SystemExit("readelf line exceeds 4096-byte bound")
        fields=line.split()
        if fields and fields[0]=="LOAD":
            if len(fields)<8: raise SystemExit(f"malformed PT_LOAD row: {line}")
            try: align=int(fields[-1],0)
            except ValueError: raise SystemExit(f"invalid PT_LOAD p_align: {line}")
            loads.append(align)
            if len(loads)>MAX_LOADS: raise SystemExit("PT_LOAD count exceeds bound")
    if not loads: raise SystemExit("readelf output contains no PT_LOAD rows")
    if any(align!=expected for align in loads): raise SystemExit(f"expected every PT_LOAD p_align={expected}, got {loads}")
    print(f"validated_pt_load_count={len(loads)} expected_p_align={expected:#x}")
if __name__=="__main__": main()
