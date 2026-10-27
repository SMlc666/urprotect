#!/data/data/com.termux/files/usr/bin/sh
set -eu

if [ "$#" -eq 3 ] && [ "$1" = "-o" ]; then
  output=$2
  source=$3
  define=
elif [ "$#" -eq 5 ] && [ "$1" = "--defsym" ] && [ "$2" = "URP_JUMP_TABLE_INDEX_CLOBBER=1" ] && [ "$3" = "-o" ]; then
  output=$4
  source=$5
  define=-DURP_JUMP_TABLE_INDEX_CLOBBER=1
else
  echo "unsupported locked Bionic fixture assembler argument shape" >&2
  exit 2
fi
case "$output:$source" in
  */host-context-*.o:host_context_*.S) ;;
  *) echo "Bionic fixture assembler paths are outside the expected source/output shape" >&2; exit 2 ;;
esac
if [ -n "$define" ]; then
  exec clang -c -Wa,--defsym,URP_JUMP_TABLE_INDEX_CLOBBER=1 -o "$output" "$source"
fi
exec clang -c -o "$output" "$source"
