#!/usr/bin/env bash
# Run before every push. Fails if anything that should stay private is about
# to be published:
#
#   1. Terms listed in .publish-blocklist (one per line, case-insensitive).
#      That file is gitignored, so the terms themselves are never published.
#   2. Files that should never be committed (Office documents, archives, CSVs,
#      .env files).
#   3. Secrets, if gitleaks is installed (https://github.com/gitleaks/gitleaks).
#   4. Commits authored with an email other than a GitHub noreply address.
#
# Usage: bash scripts/prepublish-check.sh

set -u
cd "$(git rev-parse --show-toplevel)" || exit 1

problems=0
fail() { echo "FAIL  $1"; problems=$((problems + 1)); }
ok()   { echo "ok    $1"; }

tracked=$(git ls-files --cached --others --exclude-standard)

# 1. Blocklisted terms, in tracked and to-be-added files
if [ -f .publish-blocklist ]; then
  hits=""
  while IFS= read -r term || [ -n "$term" ]; do
    term="${term%%#*}"; term="$(echo "$term" | xargs)"
    [ -z "$term" ] && continue
    found=$(printf '%s\n' "$tracked" | xargs -d '\n' grep -IilF -- "$term" 2>/dev/null)
    [ -n "$found" ] && hits+="  \"$term\" in: $(echo $found)"$'\n'
  done < .publish-blocklist
  if [ -n "$hits" ]; then fail "blocklisted terms found:"; printf '%s' "$hits"; else ok "no blocklisted terms"; fi
else
  fail ".publish-blocklist missing; create it (one private term per line)"
fi

# 2. File types that should never be published
bad=$(printf '%s\n' "$tracked" | grep -Ei '\.(docx?|xlsx?|pptx?|pdf|zip|csv)$|(^|/)\.env(\.|$)')
if [ -n "$bad" ]; then fail "files that should not be published:"; echo "$bad" | sed 's/^/  /'; else ok "no Office/archive/CSV/.env files"; fi

# 3. Secrets
if command -v gitleaks >/dev/null; then
  if gitleaks detect --no-banner --redact -q >/dev/null 2>&1 && gitleaks protect --staged --no-banner --redact -q >/dev/null 2>&1; then
    ok "gitleaks found no secrets"
  else
    fail "gitleaks reported possible secrets; run: gitleaks detect --redact -v"
  fi
else
  echo "skip  gitleaks not installed (recommended)"
fi

# 4. Commit author emails
emails=$(git log --format='%ae%n%ce' 2>/dev/null | sort -u | grep -v 'users.noreply.github.com$')
if [ -n "$emails" ]; then fail "commits with a non-noreply email:"; echo "$emails" | sed 's/^/  /'; else ok "all commit emails are noreply"; fi

echo
if [ "$problems" -eq 0 ]; then echo "Ready to publish."; else echo "$problems problem(s). Fix before pushing."; exit 1; fi
