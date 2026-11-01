#!/usr/bin/env bash
# AT7: run keysprawl on an AT3-like fake environment (fake keys generated now, in a tmp dir),
# once normally and once inside a network-less namespace under strace; compare + check syscalls.
# Usage: tests/at7_check.sh "<netns prefix, e.g. 'unshare -rn' or 'sudo unshare -n'>"
set -euo pipefail
NETNS=${1:-"unshare -rn"}
STRACE=${STRACE:-strace}
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
r() { tr -dc A-Za-z0-9 </dev/urandom | head -c "$1"; }
H=$T/home; P=$T/proj; mkdir -p "$H/.local/share/opencode" "$H/.claude" "$P"
printf '{"openai":{"type":"api","key":"%s"}}' "sk-""proj-$(r 48)" > "$H/.local/share/opencode/auth.json"
printf '{"env":{"ANTHROPIC_API_KEY":"%s"}}' "sk-""ant-api03-$(r 40)" > "$H/.claude/settings.json"
printf 'GITHUB_TOKEN=%s\n' "gh""p_$(r 36)" > "$P/.env"
printf 'export GH_TOKEN=%s\n' "github""_pat_$(r 40)" > "$H/.bashrc"
printf 'export OPENAI_API_KEY=%s\n' "sk-""proj-$(r 48)" > "$H/.zshrc.bak"
RUN=(env -i HOME="$H" USERPROFILE="$H" PATH="$PATH" PYTHONDONTWRITEBYTECODE=1 python3 -B "$HERE/keysprawl.py" --json)
cd "$P"
set +e
"${RUN[@]}" > "$T/net.json"; rc1=$?
$NETNS "$STRACE" -f -qq -e trace=network -o "$T/strace.log" "${RUN[@]}" > "$T/nonet.json"; rc2=$?
set -e
strip() { python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));d.pop("scanned_at");print(json.dumps(d,sort_keys=True))' "$1"; }
echo "exit codes: with-net=$rc1 no-net=$rc2"
[ "$rc1" = "$rc2" ] || { echo "FAIL: exit codes differ"; exit 1; }
[ "$(strip "$T/net.json")" = "$(strip "$T/nonet.json")" ] || { echo "FAIL: outputs differ"; exit 1; }
echo "outputs identical (excluding scanned_at); keys found: $(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["keys"]))' "$T/net.json")"
echo "strace network syscalls logged: $(wc -l < "$T/strace.log")"
if grep -E 'AF_INET6?' "$T/strace.log" | grep -E '\b(socket|connect)\(' ; then echo "FAIL: AF_INET/AF_INET6 socket/connect seen"; exit 1; fi
echo "PASS: no AF_INET/AF_INET6 socket/connect"
