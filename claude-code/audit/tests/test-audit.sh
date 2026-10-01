#!/usr/bin/env bash
# Builds the audit image and runs it against two fixtures:
#   good/: the guide's hardened baseline: expect exit 0 and no FAIL
#   bad/:  a deliberately insecure setup: expect exit 1 and every FAIL below
#
# Usage (from the repository root):  bash claude-code/audit/tests/test-audit.sh
# Set AUDIT_IMAGE to test an existing image instead of building one.

set -u
here="$(cd "$(dirname "$0")" && pwd)"
audit_dir="$(cd "$here/.." && pwd)"
cc_dir="$(cd "$audit_dir/.." && pwd)"
ENGINE="${CONTAINER_ENGINE:-$(command -v docker || command -v podman)}"
IMAGE="${AUDIT_IMAGE:-claude-code-audit:test}"

if [ -z "${AUDIT_IMAGE:-}" ]; then
  "$ENGINE" build -q -f "$audit_dir/Dockerfile" -t "$IMAGE" "$cc_dir" >/dev/null || { echo "build failed"; exit 1; }
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp -R "$here/fixtures/." "$work/"

# Files the repository refuses to store are created here instead.
mkdir -p "$work/good/project/.claude/hooks"
cp "$cc_dir"/hooks/*.sh "$work/good/project/.claude/hooks/"
echo 'FAKE=not-a-secret' > "$work/good/project/.env"
echo 'FAKE=not-a-secret' > "$work/bad/project/.env"

# SymJack-style links: a harmless name pointing at agent config, and one leaving the project.
# (On Windows/Git Bash, native symlinks need developer mode; without them these checks are skipped.)
export MSYS=winsymlinks:nativestrict
symlinks=0
if ln -s .claude/settings.json "$work/bad/project/SETUP-NOTES.md" 2>/dev/null \
   && ln -s /etc/passwd "$work/bad/project/users.txt" 2>/dev/null \
   && [ -L "$work/bad/project/SETUP-NOTES.md" ]; then
  symlinks=1
fi
chmod -R a+rX "$work"

native() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else echo "$1"; fi; }

run() { # run <fixture> <rc-file> <version> [format]
  local d="$work/$1" fmt="${4:-json}"
  MSYS_NO_PATHCONV=1 "$ENGINE" run --rm --network none --read-only --cap-drop ALL \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --security-opt no-new-privileges \
    -e CLAUDE_VERSION="$3" \
    -v "$(native "$d/home/.claude/settings.json"):/audit/home-claude/settings.json:ro" \
    -v "$(native "$d/home/.claude.json"):/audit/claude.json:ro" \
    -v "$(native "$d/home/$2"):/audit/rc/$2:ro" \
    -v "$(native "$d/project"):/audit/project:ro" \
    -e PROJECT_NAME="fixture-$1" \
    "$IMAGE" --format "$fmt"
}

fails=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi; }

good=$(run good .bashrc "2.1.290 (Claude Code)"); good_rc=$?
bad=$(run bad .zshrc "2.1.100 (Claude Code)"); bad_rc=$?

check "good: exit code 0"                "[ $good_rc -eq 0 ]"
check "good: no FAIL results"            "[ \$(jq '.summary.fail' <<<\"\$good\") -eq 0 ]"
check "good: no WARN results"            "[ \$(jq '.summary.warn' <<<\"\$good\") -eq 0 ]"
check "good: hooks pass their tests"     "jq -e '.checks[] | select(.id==\"H03\" and .status==\"PASS\")' <<<\"\$good\" >/dev/null"
check "bad: exit code 1"                 "[ $bad_rc -eq 1 ]"
for id in U02 U03 U09 U11 U13 U15 U16 P03 R01 $( [ "$symlinks" = 1 ] && echo P11 ); do
  check "bad: $id is FAIL" "jq -e '.checks[] | select(.id==\"$id\" and .status==\"FAIL\")' <<<\"\$bad\" >/dev/null"
done
[ "$symlinks" = 1 ] || echo "skip  P11 symlink checks (this system cannot create symlinks)"
for id in I01 U04 U05 U07 U08 U10 U12 U14 U17 P05 P06 P08 P09 P10 P12 P13 M02 $( [ "$symlinks" = 1 ] && echo P11 ); do
  check "bad: $id is WARN" "jq -e '.checks[] | select(.id==\"$id\" and .status==\"WARN\")' <<<\"\$bad\" >/dev/null"
done

check "bad: every WARN/FAIL has a fix"   "[ \$(jq '[.checks[] | select((.status==\"WARN\" or .status==\"FAIL\") and .fix==\"\")] | length' <<<\"\$bad\") -eq 0 ]"
check "bad: every WARN/FAIL explains why"  "[ \$(jq '[.checks[] | select((.status==\"WARN\" or .status==\"FAIL\") and (.why // \"\")==\"\")] | length' <<<\"\$bad\") -eq 0 ]"
check "bad: every WARN/FAIL is mapped"     "[ \$(jq '[.checks[] | select((.status==\"WARN\" or .status==\"FAIL\") and ([.frameworks[]] | add | length)==0)] | length' <<<\"\$bad\") -eq 0 ]"
check "bad: coverage lists ATLAS items"    "[ \$(jq '.coverage.mitre_atlas | length' <<<\"\$bad\") -gt 0 ]"
check "good: coverage is empty"            "[ \$(jq '[.coverage[] | length] | add' <<<\"\$good\") -eq 0 ]"
check "bad: every check has a guide link" "[ \$(jq '[.checks[] | select(.guide_url | startswith(\"https://\") | not)] | length' <<<\"\$bad\") -eq 0 ]"

# Report formats
txt=$(run bad .zshrc "2.1.100" report)
csv=$(run bad .zshrc "2.1.100" csv)
html=$(run bad .zshrc "2.1.100" html)
check "report: has a WHAT TO FIX section"  "grep -q '^WHAT TO FIX' <<<\"\$txt\""
check "report: lists fixes"                "grep -q '^     Fix:' <<<\"\$txt\""
check "csv: header row"                    "[ \"\$(head -n1 <<<\"\$csv\")\" = '\"status\",\"id\",\"guide_step\",\"title\",\"why\",\"details\",\"fix\",\"owasp_llm_2025\",\"owasp_agentic_2026\",\"mitre_atlas_2026_09\",\"nist_ai_rmf_1_0\",\"guide_url\",\"sources\"' ]"
check "every WARN/FAIL cites a source"     "[ \$(jq '[.checks[] | select((.status==\"WARN\" or .status==\"FAIL\") and ((.sources // []) | length)==0)] | length' <<<\"\$bad\") -eq 0 ]"
check "report/html show sources"           "grep -q '^     Source:  Adversa AI' <<<\"\$txt\" || grep -q '^     Source:' <<<\"\$txt\"; grep -q 'class=\"src\"' <<<\"\$html\""
check "csv: framework columns filled"      "grep -q 'AML.T0105 Escape to Host' <<<\"\$csv\" && grep -q 'ASI05 Unexpected Code Execution' <<<\"\$csv\" && grep -q 'MEASURE 2.7' <<<\"\$csv\""
check "report: explains why"               "grep -q '^     Why:' <<<\"\$txt\""
check "report: framework coverage section" "grep -q '^FRAMEWORK COVERAGE OF FINDINGS' <<<\"\$txt\" && grep -q '^MITRE ATLAS (2026.09)' <<<\"\$txt\""
check "html: why + mapping + coverage"     "grep -q 'Why it matters' <<<\"\$html\" && grep -q 'Risk mapping' <<<\"\$html\" && grep -q 'Framework coverage' <<<\"\$html\""
check "csv: one row per check"             "[ \$(( \$(wc -l <<<\"\$csv\") - 1 )) -eq \$(jq '.checks | length' <<<\"\$bad\") ]"
check "html: complete document"            "grep -q '</html>' <<<\"\$html\""
check "html: no scripts or external loads" "! grep -Eiq '<script|<link|src=|@import' <<<\"\$html\""
# The bad fixture's hook command contains <b>x</b>: it must appear escaped.
check "html: findings are HTML-escaped"    "grep -q '&lt;b&gt;x&lt;/b&gt;' <<<\"\$html\" && ! grep -q '<b>x</b>' <<<\"\$html\""

echo
if [ "$fails" -eq 0 ]; then echo "All audit tests passed."; else echo "$fails audit test(s) failed."; exit 1; fi
