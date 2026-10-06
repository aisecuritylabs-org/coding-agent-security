#!/usr/bin/env bash
# Shared parts of the AISecurityLabs.org coding-agent audits: argument parsing,
# result recording with secret redaction, JSON/TOML/JSONC helpers, common
# repository checks and the five report formats.
#
# A product audit sets these, defines guide_page() and fix_for(), sources this
# file, runs its checks, then calls render_report:
#   PRODUCT        display name, e.g. "GitHub Copilot"
#   TOOL           image name, e.g. "copilot-audit"
#   VERSION_LABEL  e.g. "VS Code"; PRODUCT_VERSION holds the value
#   AUDIT_VERSION, GUIDE_URL, GUIDE_NAME, MAPPINGS, TMP

set -u

FORMAT=text
while [ $# -gt 0 ]; do
  case "$1" in
    --json) FORMAT=json ;;
    --format) FORMAT="${2:-}"; shift ;;
    --format=*) FORMAT="${1#--format=}" ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "usage: audit.sh [--format text|report|json|csv|html]" >&2; exit 2 ;;
  esac
  shift
done
case "$FORMAT" in
  text|report|json|csv|html) ;;
  *) echo "unknown format '$FORMAT' (use text, report, json, csv or html)" >&2; exit 2 ;;
esac

results=()
n_pass=0 n_warn=0 n_fail=0 n_info=0

# Details quote hook commands, MCP arguments and URLs. Mask anything that looks
# like a secret before it reaches the screen or a saved report.
REDACT='def redact:
  gsub("(?<s>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\\s]+@"; "\(.s)***@")
  | gsub("(?i)(?<k>[?&](token|key|api[_-]?key|access_token|secret|password|passwd|sig|signature|auth|code)=)[^&\\s\"'"'"']+"; "\(.k)***")
  | gsub("(?i)(?<k>\\b[a-z0-9_]*(token|secret|password|passwd|api_?key|credential)[a-z0-9_]*=)[^\\s\"'"'"']+"; "\(.k)***")
  | gsub("(?i)(?<k>--?(token|api-?key|password|passwd|secret|auth)[= ])[^\\s\"'"'"']+"; "\(.k)***")
  | gsub("(?i)(?<k>(bearer|basic) )[a-z0-9._~+/=-]+"; "\(.k)***")
  | gsub("(?<k>ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|sk-|sk_live_|xox[bpas]-|AKIA)[A-Za-z0-9_-]{8,}"; "\(.k)***");'

# record <STATUS> <id> <guide-step> <title> [detail]
record() {
  local status="$1" id="$2" step="$3" title="$4" detail="${5:-}"
  case "$status" in
    PASS) n_pass=$((n_pass + 1)) ;;
    WARN) n_warn=$((n_warn + 1)) ;;
    FAIL) n_fail=$((n_fail + 1)) ;;
    INFO) n_info=$((n_info + 1)) ;;
  esac
  local fix="" url
  case "$status" in WARN|FAIL) fix="$(fix_for "$id")" ;; esac
  url="$GUIDE_URL$(guide_page "$step")"
  results+=("$(jq -cn --arg s "$status" --arg i "$id" --arg g "$step" --arg t "$title" --arg d "$detail" \
    --arg f "$fix" --arg u "$url" \
    "$REDACT"'{status:$s, id:$i, guide_step:$g, title:$t, detail:($d | redact), fix:$f, guide_url:$u}')")
}

# toml <file> <cache-name>: convert a TOML file to JSON in $TMP; fails on invalid TOML.
toml() { [ -f "$1" ] && yq -p toml -o json . "$1" > "$TMP/$2.json" 2>/dev/null; }

# q <json-file> <jq-filter>: run a jq filter, empty output on any error
q() { [ -f "$1" ] && jq -r "$2" "$1" 2>/dev/null; }

version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# jsonc <file> <cache-name>: convert JSON with comments (VS Code-style
# settings) to JSON in $TMP; fails on invalid input, including an unterminated
# comment or more than one JSON value. A file with only comments or whitespace
# counts as an empty object, as editors treat it.
jsonc() {
  local text
  [ -f "$1" ] || return 1
  text=$(awk -f "${JSONC_AWK:-/opt/audit/jsonc.awk}" "$1") || return 1
  [ -z "${text//[[:space:]]/}" ] && text='{}'
  jq -s 'if length == 1 then .[0] else error("more than one value") end' <<<"$text" > "$TMP/$2.json" 2>/dev/null
}

# Strings that look like instructions to fetch or run code, in agent instruction files.
FETCH_PATTERN='curl |wget |\| *(ba)?sh|npm install -g|pip install|iex|Invoke-WebRequest|https?://[^ )]*\.(sh|ps1)'

# MCP servers whose name, command, args or URL suggest they read content other
# people can write (error trackers, tickets, chat, email, forges). Agentjacking.
# Usage: mcp_third_party <json-file> <jq path to the server map>
mcp_third_party() {
  q "$1" "($2) // {} | to_entries[]
    | select(([.key, (.value.command // \"\"), ((.value.args // []) | join(\" \")), (.value.url // \"\")] | join(\" \"))
             | test(\"sentry|jira|atlassian|confluence|linear|slack|discord|teams|gmail|outlook|imap|e-?mail|zendesk|intercom|pagerduty|datadog|github|gitlab|notion|hubspot\"; \"i\"))
    | .key"
}
# mcp_unpinned <json-file> <jq path to the server map>: npx/uvx servers without a version.
mcp_unpinned() {
  q "$1" "($2) // {} | to_entries[] | select((.value.command // \"\" | test(\"npx|uvx|bunx|pnpm\")) and (((.value.args // []) | map(select(test(\"^@?[a-z0-9._-]+(/[a-z0-9._-]+)?(@latest)?$\"; \"i\"))) | length) > 0)) | .key"
}
# mcp_list <json-file> <jq path>: "name: command args" or "name: url" per server.
mcp_list() {
  q "$1" "($2) // {} | to_entries[] | \"\\(.key): \\(.value.command // .value.url // \"?\") \\((.value.args // []) | join(\" \"))\""
}

# hidden_unicode <file...>: files containing zero-width or bidi control
# characters, the "Rules File Backdoor" technique.
hidden_unicode() {
  local f
  for f in "$@"; do
    [ -f "$f" ] || continue
    if LC_ALL=C grep -q $'\xe2\x80[\x8b-\x8f\xaa-\xae]\|\xe2\x81[\xa0-\xa4]\|\xef\xbb\xbf' "$f" 2>/dev/null; then
      echo "${f#$PROJECT/}"
    fi
  done
}

# Common project checks, recorded under the IDs the caller passes.
# check_symlinks <id> <step> <sensitive-target-regex>
check_symlinks() {
  local id="$1" step="$2" re="$3" link rel target depth sensitive_links="" outside_links=""
  while IFS= read -r link; do
    [ -z "$link" ] && continue
    rel="${link#$PROJECT/}"; target=$(readlink "$link")
    if grep -Eq "$re" <<<"$target"; then
      sensitive_links+="$rel -> $target"$'\n'
    else
      case "$target" in
        /*) outside_links+="$rel -> $target"$'\n' ;;
        *)  depth=$(awk -F/ -v p="$(dirname "$rel")/$target" 'BEGIN{n=split(p,a,"/"); d=0; for(i=1;i<=n;i++){ if(a[i]==".."){d--; if(d<0){print "out"; exit}} else if(a[i]!="." && a[i]!=""){d++} } print "in"}')
            [ "$depth" = "out" ] && outside_links+="$rel -> $target"$'\n' ;;
      esac
    fi
  done < <(find "$PROJECT" \( -name .git -o -name node_modules -o -name .venv -o -name vendor \) -prune -o -type l -print 2>/dev/null | head -n 500)
  [ -n "$sensitive_links" ] && record FAIL "$id" "$step" "Symlinks point at agent configuration or dotfiles" "$(head -n 20 <<<"$sensitive_links")"
  [ -n "$outside_links" ]   && record WARN "$id" "$step" "Symlinks point outside the project" "$(head -n 20 <<<"$outside_links")"
  return 0
}
# check_gitconfig <id> <step>: .git/config keys that make git run programs.
check_gitconfig() {
  local gitexec
  [ -f "$PROJECT/.git/config" ] || return 0
  gitexec=$(grep -Ei '^[[:space:]]*(hookspath|fsmonitor|sshcommand|pager|editor|askpass|process|clean|smudge|textconv|tree)[[:space:]]*=' "$PROJECT/.git/config" | sed 's/^[[:space:]]*//' || true)
  [ -n "$gitexec" ] && record WARN "$1" "$2" ".git/config makes git run programs" "$gitexec"
  return 0
}
# check_env_gitignored <id> <step>
# .env and .gitignore checks live in gitignore.sh, shared with the older audits.
# shellcheck source=gitignore.sh
. "${GITIGNORE_LIB:-$(dirname "${BASH_SOURCE[0]}")/gitignore.sh}"
# check_rc_flags <id> <step> <regex> <title>: shell startup files that use risky flags.
check_rc_flags() {
  local hits
  [ -d "$RC_DIR" ] || return 0
  hits=$(grep -l -E -- "$3" "$RC_DIR"/.[a-zA-Z]* "$RC_DIR"/* 2>/dev/null | xargs -r -n1 basename | sort -u)
  if [ -n "$hits" ]; then
    record FAIL "$1" "$2" "$4" "$(echo $hits)"
  elif [ -n "$(ls -A "$RC_DIR" 2>/dev/null)" ]; then
    record PASS "$1" "$2" "No risky aliases in shell startup files"
  fi
}
project_mounted() { [ -d "$PROJECT" ] && [ -n "$(ls -A "$PROJECT" 2>/dev/null)" ]; }

render_report() {
  # --------------------------------------------------------------- report ----

  generated="$(date -u '+%Y-%m-%d %H:%M UTC')"
  project_label="${PROJECT_NAME:-}"
  [ -z "$project_label" ] && [ -d "$PROJECT" ] && project_label="(mounted project)"
  [ -z "$project_label" ] && project_label="(none)"

  doc=$(printf '%s\n' "${results[@]}" | jq -s \
    --arg v "$AUDIT_VERSION" --arg gen "$generated" --arg proj "$project_label" \
    --arg os "${HOST_OS:-linux/macos}" --arg cv "${PRODUCT_VERSION:-unknown}" --arg tool "$TOOL" \
    --argjson p "$n_pass" --argjson w "$n_warn" --argjson f "$n_fail" --argjson i "$n_info" \
    '{tool:$tool, version:$v, generated:$gen, project:$proj, host_os:$os,
      product_version:$cv, summary:{pass:$p, warn:$w, fail:$f, info:$i},
      checks: (map(. + {order: {FAIL:0, WARN:1, INFO:2, PASS:3}[.status]}) | sort_by(.order) | map(del(.order)))}')

  if [ -f "$MAPPINGS" ]; then
    doc=$(jq --slurpfile map "$MAPPINGS" '
      $map[0] as $m
      | def fw($id; $k): [($m.checks[$id][$k] // [])[] | {id: ., title: $m.frameworks[$k].items[.]}];
        def keys4: ["owasp_llm", "owasp_agentic", "mitre_atlas", "nist_ai_rmf"];
      .checks |= map(. as $c | . + {
          why: ($m.checks[$c.id].why // ""),
          sources: ($m.checks[$c.id].sources // []),
          frameworks: (reduce keys4[] as $k ({}; .[$k] = fw($c.id; $k)))
        })
      | .frameworks = (reduce keys4[] as $k ({}; .[$k] = ($m.frameworks[$k] | {name, version, url})))
      | ([.checks[] | select(.status == "FAIL" or .status == "WARN")]) as $todo
      | .coverage = (reduce keys4[] as $k ({};
          .[$k] = ([ $todo[] | . as $c | .frameworks[$k][] | {id, title, check: $c.id, status: $c.status} ]
                   | group_by(.id)
                   | map({id: .[0].id, title: .[0].title,
                          fail: (map(select(.status == "FAIL")) | length),
                          warn: (map(select(.status == "WARN")) | length),
                          checks: (map(.check) | unique)})
                   | sort_by(-.fail, -.warn, .id))))
    ' <<<"$doc")
  fi

  SELF_TEST="${SELF_TEST_URL:-$GUIDE_URL#6-self-test}"

  case "$FORMAT" in
    json)
      jq . <<<"$doc"
      ;;

    text)
      echo "$PRODUCT security audit v$AUDIT_VERSION (read-only, offline)"
      echo "Guide: $GUIDE_NAME, step numbers shown in [brackets]"
      echo
      for r in "${results[@]}"; do
        jq -r '"\(.status | . + "    " | .[0:5]) [\(.guide_step)] \(.title)" + (.detail | split("\n") | map(select(. != "") | "\n              " + .) | join(""))' <<<"$r"
      done
      echo
      echo "Summary: $n_pass pass, $n_warn warn, $n_fail fail, $n_info info"
      ;;

    report)
      jq -r --arg selftest "$SELF_TEST" --arg product "$PRODUCT" --arg vlabel "$VERSION_LABEL" '
        (($product | ascii_upcase) + " SECURITY AUDIT REPORT"),
        ("=" * (($product | length) + 22)),
        "Generated:      \(.generated)",
        "Project:        \(.project)",
        "Host:           \(.host_os)",
        "\(($vlabel + ":               ")[0:16])\(.product_version)",
        "Audit version:  \(.version)",
        "",
        "Summary: \(.summary.fail) FAIL, \(.summary.warn) WARN, \(.summary.pass) PASS, \(.summary.info) INFO",
        "",
        ( .checks | map(select(.status == "FAIL" or .status == "WARN")) as $todo
          | if ($todo | length) == 0 then "Nothing to fix. Re-run after every \($product) upgrade." else
            "WHAT TO FIX (most serious first)",
            "--------------------------------",
            ( $todo | to_entries[] |
              "",
              "\(.key + 1). [\(.value.status)] \(.value.title)   (\(.value.id), guide step \(.value.guide_step))",
              ( if (.value.why // "") != "" then "     Why:     \(.value.why)" else empty end ),
              ( .value.detail | split("\n") | map(select(. != ""))[] | "     Details: \(.)" ),
              "     Fix:     \(.value.fix)",
              ( .value.frameworks // {} | to_entries[] | select(.value | length > 0)
                | "     \({owasp_llm: "OWASP LLM:", owasp_agentic: "OWASP Agentic:", mitre_atlas: "MITRE ATLAS:", nist_ai_rmf: "NIST AI RMF:"}[.key] | . + "       " | .[0:15]) \(.value | map("\(.id) \(if (.id | startswith("GOVERN") or startswith("MAP") or startswith("MEASURE") or startswith("MANAGE")) then "" else .title end)" | rtrimstr(" ")) | join("; "))" ),
              "     Guide:   \(.value.guide_url)",
              ( (.value.sources // [])[] | "     Source:  \(.title): \(.url)" ) )
            end ),
        ( if (.coverage // null) != null then
            "",
            "FRAMEWORK COVERAGE OF FINDINGS",
            "------------------------------",
            "Which framework risks your FAIL / WARN findings relate to (fails, warns, check IDs).",
            ( .frameworks as $fw | .coverage | to_entries[] |
              "",
              "\($fw[.key].name) (\($fw[.key].version))",
              ( if (.value | length) == 0 then "  none" else
                ( .value[] | "  \(.id) \(.title | if length > 70 then .[0:67] + "..." else . end): \(.fail) FAIL, \(.warn) WARN  [\(.checks | join(", "))]" ) end ) )
          else empty end ),
        "",
        "PASSED AND INFORMATIONAL",
        "------------------------",
        ( .checks[] | select(.status == "PASS" or .status == "INFO") | "[\(.status)] \(.title)" ),
        "",
        "Framework mappings are AISecurityLabs.org'"'"'s interpretation, verified against",
        "OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026, MITRE ATLAS 2026.09 and",
        "NIST AI RMF 1.0. They are not endorsed by the framework owners.",
        "",
        "This audit reads configuration only. To prove the controls work in a live",
        "session, run the self-test: \($selftest)"
      ' <<<"$doc"
      ;;

    csv)
      jq -r '
        def ids($k): (.frameworks[$k] // []) | map(.id + (if $k == "nist_ai_rmf" then "" else " " + .title end)) | join("; ");
        ["status","id","guide_step","title","why","details","fix","owasp_llm_2025","owasp_agentic_2026","mitre_atlas_2026_09","nist_ai_rmf_1_0","guide_url","sources"],
        (.checks[] | [.status, .id, .guide_step, .title, (.why // ""), (.detail | gsub("\n"; "; ")), .fix,
                      ids("owasp_llm"), ids("owasp_agentic"), ids("mitre_atlas"), ids("nist_ai_rmf"), .guide_url,
                      ((.sources // []) | map("\(.title) <\(.url)>") | join("; "))])
        | @csv
      ' <<<"$doc"
      ;;

    html)
      jq -r --arg selftest "$SELF_TEST" --arg product "$PRODUCT" --arg vlabel "$VERSION_LABEL" --arg tool "$TOOL" '
        def badge: "<span class=\"b \(. | ascii_downcase)\">\(.)</span>";
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>\($product | @html) security audit: \(.project | @html)</title>",
        "<style>",
        "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1f2937;background:#fff;line-height:1.55}",
        "h1{margin:0 0 .25rem;color:#0d0d0d}h2{margin-top:2.5rem;border-bottom:1px solid #d1d9e0;padding-bottom:.3rem;color:#0d0d0d}",
        ".meta{color:#59636e;font-size:.9rem}.sum{display:flex;gap:.75rem;flex-wrap:wrap;margin:1.25rem 0}",
        ".sum div{background:#f6f8fa;border:1px solid #d1d9e0;border-radius:6px;padding:.6rem 1rem;min-width:6rem}",
        ".sum strong{display:block;font-size:1.6rem}",
        ".card{background:#fff;border:1px solid #d1d9e0;border-left:5px solid #999;border-radius:6px;padding:1rem 1.25rem;margin:1rem 0}",
        ".card.fail{border-left-color:#b42318}.card.warn{border-left-color:#d4a72c}",
        ".card h3{margin:.2rem 0 .5rem;font-size:1.05rem}.id{color:#59636e;font-weight:400;font-size:.85rem}",
        ".b{display:inline-block;font-size:.72rem;font-weight:700;padding:.1rem .5rem;border-radius:999px;color:#fff;letter-spacing:.04em}",
        ".b.fail{background:#b42318}.b.warn{background:#a8801a}.b.pass{background:#1f5fa8}.b.info{background:#4a5568}",
        "pre{background:#f6f8fa;border:1px solid #d1d9e0;border-radius:6px;padding:.6rem .8rem;white-space:pre-wrap;word-break:break-word;margin:.25rem 0 .75rem;font-size:.85rem}",
        ".label{font-weight:600;font-size:.85rem;margin-top:.5rem}a{color:#1e3a8a}",
        "table{border-collapse:collapse;width:100%;background:#fff}td{border-bottom:1px solid #d1d9e0;padding:.45rem .6rem;vertical-align:top}",
        ".foot{margin-top:2.5rem;font-size:.85rem;color:#59636e}",
        ".why{margin:.25rem 0 .5rem}.map{width:100%;margin:.5rem 0 .75rem;font-size:.82rem}.map td{border:none;border-top:1px solid #eaeef2;padding:.3rem .5rem}",
        ".map td:first-child{white-space:nowrap;font-weight:600;color:#59636e;width:9rem}",
        ".chip{display:inline-block;background:#f6f8fa;border:1px solid #d1d9e0;border-radius:4px;padding:.05rem .4rem;margin:.1rem .25rem .1rem 0}",
        ".chip b{font-weight:600}.cov td{font-size:.85rem}.cov th{text-align:left;font-size:.8rem;color:#59636e;padding:.4rem .6rem;border-bottom:2px solid #d1d9e0}",
        ".n{text-align:right;white-space:nowrap}.small{font-size:.8rem;color:#59636e}",
        ".src{margin:.2rem 0 .75rem 1.1rem;padding:0;font-size:.82rem}.src li{margin:.1rem 0}",
        "</style></head><body>",
        "<h1>\($product | @html) security audit</h1>",
        "<p class=\"meta\">Project: <strong>\(.project | @html)</strong> · Generated \(.generated | @html) · Host: \(.host_os | @html) · \($vlabel | @html): \(.product_version | @html) · Audit v\(.version | @html)</p>",
        "<div class=\"sum\"><div><strong>\(.summary.fail)</strong>FAIL</div><div><strong>\(.summary.warn)</strong>WARN</div><div><strong>\(.summary.pass)</strong>PASS</div><div><strong>\(.summary.info)</strong>INFO</div></div>",
        ( .checks | map(select(.status == "FAIL" or .status == "WARN")) as $todo
          | "<h2>What to fix</h2>",
            ( if ($todo | length) == 0 then "<p>Nothing to fix. Re-run after every \($product) upgrade.</p>" else
              ( $todo[] |
                "<div class=\"card \(.status | ascii_downcase)\">",
                "<h3>\(.status | badge) \(.title | @html) <span class=\"id\">\(.id) · guide step \(.guide_step)</span></h3>",
                ( if (.why // "") != "" then "<div class=\"label\">Why it matters</div><p class=\"why\">\(.why | @html)</p>" else empty end ),
                ( if .detail != "" then "<div class=\"label\">Details</div><pre>\(.detail | @html)</pre>" else empty end ),
                "<div class=\"label\">How to fix</div><pre>\(.fix | @html)</pre>",
                ( if (.frameworks // {} | [.[]] | add // [] | length) > 0 then
                    "<div class=\"label\">Risk mapping</div><table class=\"map\">",
                    ( .frameworks | to_entries[] | select(.value | length > 0)
                      | "<tr><td>\({owasp_llm: "OWASP LLM Top 10", owasp_agentic: "OWASP Agentic Top 10", mitre_atlas: "MITRE ATLAS", nist_ai_rmf: "NIST AI RMF"}[.key])</td><td>\(.key as $k | .value | map("<span class=\"chip\"\(if $k == "nist_ai_rmf" then " title=\"" + (.title | @html) + "\"" else "" end)><b>\(.id | @html)</b>\(if $k == "nist_ai_rmf" then "" else " " + (.title | @html) end)</span>") | join(""))</td></tr>" ),
                    "</table>"
                  else empty end ),
                ( if (.sources // [] | length) > 0 then
                    "<div class=\"label\">Sources</div><ul class=\"src\">",
                    ( .sources[] | "<li><a href=\"\(.url | @html)\">\(.title | @html)</a></li>" ),
                    "</ul>"
                  else empty end ),
                "<a href=\"\(.guide_url | @html)\">Read guide step \(.guide_step)</a>",
                "</div>" )
              end ) ),
        ( if (.coverage // null) != null then
            "<h2>Framework coverage</h2>",
            "<p class=\"small\">Which framework risks your FAIL and WARN findings relate to. Use this to report against your organisation'"'"'s AI risk framework.</p>",
            ( .frameworks as $fw | .coverage | to_entries[] |
              "<h3>\($fw[.key].name | @html) <span class=\"id\">\($fw[.key].version | @html)</span></h3>",
              ( if (.value | length) == 0 then "<p class=\"small\">No findings relate to this framework.</p>" else
                  "<table class=\"cov\"><tr><th>ID</th><th>\(if .key == "nist_ai_rmf" then "Subcategory" else "Risk / technique" end)</th><th class=\"n\">FAIL</th><th class=\"n\">WARN</th><th>Checks</th></tr>",
                  ( .value[] | "<tr><td><b>\(.id | @html)</b></td><td>\(.title | @html)</td><td class=\"n\">\(.fail)</td><td class=\"n\">\(.warn)</td><td class=\"small\">\(.checks | join(", ") | @html)</td></tr>" ),
                  "</table>"
                end ),
              "<p class=\"small\"><a href=\"\($fw[.key].url | @html)\">About \($fw[.key].name | @html)</a></p>" )
          else empty end ),
        "<h2>Passed and informational</h2><table>",
        ( .checks[] | select(.status == "PASS" or .status == "INFO")
          | "<tr><td>\(.status | badge)</td><td>\(.title | @html)\(if .detail != "" then "<br><small>\(.detail | @html)</small>" else "" end)</td><td class=\"id\">\(.id)</td></tr>" ),
        "</table>",
        "<p class=\"foot\">Framework mappings are AISecurityLabs.org'"'"'s interpretation, verified against OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications 2026, MITRE ATLAS 2026.09 and NIST AI RMF 1.0; they are not endorsed by the framework owners.</p>",
        "<p class=\"foot\">This audit reads configuration only. To prove the controls work in a live session, run the <a href=\"\($selftest | @html)\">self-test</a>. Generated offline by \($tool); this file loads no external resources.</p>",
        "</body></html>"
      ' <<<"$doc"
      ;;
  esac

  [ "$n_fail" -eq 0 ]

}
