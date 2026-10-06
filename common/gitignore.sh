#!/usr/bin/env bash
# Offline .gitignore and git index checks for the coding-agent audits.
#
# Git isn't available in the audit containers, so these functions read the
# project's root .gitignore and .git/info/exclude as text and apply git's
# matching rules for the patterns they support:
#   - a pattern with a slash at the start or in the middle is anchored to the
#     root; without one it matches a name at any depth;
#   - a trailing slash matches directories only;
#   - "*" and "?" never match "/"; "**/name" at the start means the name at any
#     depth;
#   - "dir/**" (anchored) matches everything inside dir, files and folders, but
#     not dir itself, so a later "!dir/file" can still re-include a file in it;
#   - the last matching pattern wins and "!" negates it, but nothing inside an
#     excluded directory can be re-included.
# Anything else (backslash escapes, "**" elsewhere, such as "**/a/b",
# "**/dir/**" or "a/**/b", nested .gitignore files, an index format it can't
# read) makes the answer "uncertain" rather than a pass. Needs: PROJECT, and
# record() from the calling audit.

# gi_rules: print "neg<TAB>anchored<TAB>kind<TAB>pattern" per rule, or return 2
# if a pattern uses syntax this matcher doesn't support. kind: 0 matches files
# and folders, 1 folders only (trailing slash), 2 everything inside (dir/**).
gi_rules() {
  local f line neg anch kind anydepth
  for f in "$PROJECT/.git/info/exclude" "$PROJECT/.gitignore"; do
    [ -f "$f" ] || continue
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%$'\r'}"
      # Trailing spaces are ignored unless escaped; escapes aren't supported.
      case "$line" in *\\*) return 2 ;; esac
      line="$(sed 's/[[:space:]]*$//' <<<"$line")"
      case "$line" in ''|'#'*) continue ;; esac
      neg=0; case "$line" in '!'*) neg=1; line="${line#!}" ;; esac
      kind=0; case "$line" in */) kind=1; line="${line%/}" ;; esac
      case "$line" in
        */\*\*)
          [ "$kind" -eq 1 ] && return 2            # "dir/**/"
          line="${line%/\*\*}"; kind=2 ;;
      esac
      anydepth=0; case "$line" in '**/'*) anydepth=1; line="${line#\*\*/}" ;; esac
      anch=0
      case "$line" in
        /*)  line="${line#/}"; anch=1 ;;
        */*) anch=1 ;;
      esac
      if [ "$anydepth" -eq 1 ]; then
        # "**/name" is the same as "name"; "**/a/b" and "**/dir/**" aren't modelled.
        { [ "$anch" -eq 1 ] || [ "$kind" -eq 2 ]; } && return 2
      fi
      # "dir/**" is anchored even without another slash: it contains one.
      [ "$kind" -eq 2 ] && anch=1
      case "$line" in *'**'*) return 2 ;; esac   # "**" anywhere else
      [ -z "$line" ] && return 2                  # "/**", "**/" and the like
      printf '%s\t%s\t%s\t%s\n' "$neg" "$anch" "$kind" "$line"
    done < "$f"
  done
}

# gi_prefix_match <pattern> <path>: path is strictly inside the folder the
# pattern names (more segments, and the leading ones match).
gi_prefix_match() {
  local -a p q
  local i
  IFS=/ read -r -a p <<<"$1"
  IFS=/ read -r -a q <<<"$2"
  [ "${#q[@]}" -gt "${#p[@]}" ] || return 1
  for i in "${!p[@]}"; do
    # shellcheck disable=SC2254
    case "${q[$i]}" in ${p[$i]}) ;; *) return 1 ;; esac
  done
}

# gi_segments_match <pattern> <path>: both split on "/", same depth, each
# segment matched as a glob (so "*" can't cross a slash).
gi_segments_match() {
  local -a p q
  local i
  IFS=/ read -r -a p <<<"$1"
  IFS=/ read -r -a q <<<"$2"
  [ "${#p[@]}" -eq "${#q[@]}" ] || return 1
  for i in "${!p[@]}"; do
    # shellcheck disable=SC2254
    case "${q[$i]}" in ${p[$i]}) ;; *) return 1 ;; esac
  done
}

# gi_decide <path> <is_dir> <rules>: 0 ignored, 1 not ignored (last match wins).
gi_decide() {
  local path="$1" isdir="$2" rules="$3" name="${1##*/}" neg anch kind pat state=1
  while IFS=$'\t' read -r neg anch kind pat; do
    [ -z "$pat" ] && continue
    [ "$kind" -eq 1 ] && [ "$isdir" -eq 0 ] && continue
    if [ "$kind" -eq 2 ]; then gi_prefix_match "$pat" "$path" || continue
    elif [ "$anch" -eq 1 ]; then gi_segments_match "$pat" "$path" || continue
    else gi_segments_match "$pat" "$name" || continue; fi
    if [ "$neg" -eq 1 ]; then state=1; else state=0; fi
  done <<<"$rules"
  return "$state"
}

# gitignore_ignores <relative file path>: 0 ignored, 1 not ignored, 2 uncertain.
gitignore_ignores() {
  local rel="$1" rules d prefix="" rc
  rules=$(gi_rules); rc=$?
  [ "$rc" -eq 2 ] && return 2
  # A .gitignore below the root could change the answer for files under it.
  d="${rel%/*}"
  if [ "$d" != "$rel" ]; then
    local part; local -a parts
    IFS=/ read -r -a parts <<<"$d"
    for part in "${parts[@]}"; do
      prefix="${prefix:+$prefix/}$part"
      [ -f "$PROJECT/$prefix/.gitignore" ] && return 2
      # An excluded parent directory can't have files re-included.
      gi_decide "$prefix" 1 "$rules" && return 0
    done
  fi
  gi_decide "$rel" 0 "$rules"
}

# git_tracks <relative path>: 0 tracked, 1 not tracked, 2 uncertain.
# Index versions 2 and 3 store each path in full, ending in a NUL byte.
git_tracks() {
  local idx="$PROJECT/.git/index" ver
  [ -d "$PROJECT/.git" ] || return 1
  [ -f "$idx" ] || return 1
  [ "$(head -c 4 "$idx" 2>/dev/null)" = "DIRC" ] || return 2
  ver=$(od -An -tu1 -j7 -N1 "$idx" 2>/dev/null | tr -d ' ')
  case "$ver" in 2|3) ;; *) return 2 ;; esac
  tr '\0' '\n' < "$idx" 2>/dev/null | awk -v r="$1" '
    { n = length($0); m = length(r)
      if (n >= m && substr($0, n - m + 1) == r && (n == m || substr($0, n - m, 1) !~ /[[:print:]]/)) { f = 1; exit } }
    END { exit !f }'
}

# check_env_gitignored <id> <step>: .env files that git could commit.
check_env_gitignored() {
  local f rel unignored="" tracked="" unsure="" found=0 rc
  while IFS= read -r f; do
    rel="${f#$PROJECT/}"
    case "${rel##*/}" in .env.example|.env.sample|.env.template|.env.dist|*.example|*.sample|*.template) continue ;; esac
    found=1
    gitignore_ignores "$rel"; rc=$?
    case "$rc" in 1) unignored+="$rel"$'\n' ;; 2) unsure+="$rel (.gitignore)"$'\n' ;; esac
    git_tracks "$rel"; rc=$?
    case "$rc" in 0) tracked+="$rel"$'\n' ;; 2) unsure+="$rel (git index)"$'\n' ;; esac
  done < <(find "$PROJECT" -maxdepth 3 \( -name .git -o -name node_modules -o -name .venv -o -name vendor \) -prune -o -type f -name '.env*' -print 2>/dev/null | sort)
  [ "$found" -eq 1 ] || return 0
  [ -n "$tracked" ] && record WARN "$1" "$2" ".env files are already committed to git" "$tracked"$'\n'"Remove them from git (git rm --cached) and rotate the secrets they hold."
  [ -n "$unignored" ] && record WARN "$1" "$2" ".env files are not covered by .gitignore" "$unignored"$'\n'"They can be committed by accident."
  if [ -z "$tracked$unignored" ]; then
    if [ -n "$unsure" ]; then
      record INFO "$1" "$2" "Could not confirm that .env files are ignored" "$unsure""The patterns or index use features this offline check doesn't read. Confirm with: git check-ignore -v <file>"
    else
      record PASS "$1" "$2" ".env files are covered by .gitignore" "A text check of the root .gitignore and .git/info/exclude; confirm with: git check-ignore -v .env"
    fi
  fi
}
