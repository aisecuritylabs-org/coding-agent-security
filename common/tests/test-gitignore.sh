#!/usr/bin/env bash
# Unit tests for common/gitignore.sh: the offline .gitignore matcher shared by
# every audit. Needs only bash and coreutils.
# Usage (from the repository root):  bash common/tests/test-gitignore.sh

set -u
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../gitignore.sh
. "$here/../gitignore.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fails=0

# expect <gitignore contents> <file> <0 ignored | 1 not ignored | 2 uncertain> <label>
expect() {
  PROJECT="$work/p$RANDOM$RANDOM"
  mkdir -p "$PROJECT/$(dirname "$2")"
  printf '%b' "$1" > "$PROJECT/.gitignore"
  : > "$PROJECT/$2"
  gitignore_ignores "$2"; local rc=$?
  if [ "$rc" -eq "$3" ]; then echo "ok    $4"; else echo "FAIL  $4 (got $rc, want $3)"; fails=$((fails + 1)); fi
}

expect '.env\n'            '.env'               0 'plain name at the root'
expect '.env\n'            'app/.env'           0 'plain name at any depth'
expect '/.env\n'           '.env'               0 'anchored pattern at the root'
expect '/.env\n'           'nested/.env'        1 'anchored pattern does not match below the root'
expect '.env/\n'           '.env'               1 'directory-only pattern does not match a file'
expect 'config/\n'         'config/.env'        0 'directory-only pattern ignores files inside'
expect '.env*\n'           '.env.local'         0 'glob suffix'
expect '.env.example\n'    '.env'               1 'a different name does not match'
expect '.env*\n!.env\n'    '.env'               1 'negation re-includes'
expect '!.env\n.env*\n'    '.env'               0 'later rule wins'
expect 'config\n!config/.env\n' 'config/.env'   0 'no re-include inside an excluded directory'
expect 'app/*.env\n'       'app/x.env'          0 'anchored glob in one folder'
expect 'app/*.env\n'       'app/sub/x.env'      1 'anchored "*" does not cross a slash'
expect '**/.env\n'         'a/b/.env'           0 'leading **/ matches any depth'
expect 'app/**\n'          'app/x/.env'         0 'trailing /** ignores everything inside'
expect 'config/**\n'       'config/.env'        0 'dir/** ignores a file inside'
expect 'config/**\n!config/.env\n' 'config/.env' 1 'dir/** contents can be re-included (the folder itself is not excluded)'
expect 'config/**\n'       'nested/config/.env' 1 'dir/** stays anchored to the root'
expect 'config/**\n!config/sub/.env\n' 'config/sub/.env' 0 'dir/** excludes subfolders, so files in them stay ignored'
expect '/config/**\n'      'config/.env'        0 'a leading slash on dir/** is accepted'
expect 'a/**/b\n'          'a/x/b'              2 '"**" in the middle is uncertain'
expect '**/a/b\n'          'x/a/b'              2 '"**/" followed by a path is uncertain'
expect '**/config/**\n'    'x/config/.env'      2 '"**/dir/**" is uncertain'
expect 'config/**/\n'      'config/x/.env'      2 '"dir/**/" is uncertain'
expect '\\#x\n'            '.env'               2 'escapes are uncertain'
expect '# .env\n'          '.env'               1 'comments are not patterns'

# A .gitignore below the root makes the answer uncertain.
PROJECT="$work/nested"; mkdir -p "$PROJECT/app"
printf '.env\n' > "$PROJECT/.gitignore"; printf '!.env\n' > "$PROJECT/app/.gitignore"; : > "$PROJECT/app/.env"
gitignore_ignores app/.env; rc=$?
if [ "$rc" -eq 2 ]; then echo "ok    nested .gitignore is uncertain"; else echo "FAIL  nested .gitignore (got $rc)"; fails=$((fails + 1)); fi

# .git/info/exclude counts, before .gitignore.
PROJECT="$work/exclude"; mkdir -p "$PROJECT/.git/info"
printf '.env\n' > "$PROJECT/.git/info/exclude"; : > "$PROJECT/.env"
gitignore_ignores .env; rc=$?
if [ "$rc" -eq 0 ]; then echo "ok    .git/info/exclude is read"; else echo "FAIL  .git/info/exclude (got $rc)"; fails=$((fails + 1)); fi

# Index: version 2 is read; an unknown version is uncertain.
PROJECT="$work/index"; mkdir -p "$PROJECT/.git"
printf 'DIRC\0\0\0\2\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\4.env\0\0\0\0\0' > "$PROJECT/.git/index"
git_tracks .env; rc=$?
if [ "$rc" -eq 0 ]; then echo "ok    tracked .env found in a v2 index"; else echo "FAIL  v2 index (got $rc)"; fails=$((fails + 1)); fi
git_tracks .env.local; rc=$?
if [ "$rc" -eq 1 ]; then echo "ok    a longer name is not a match"; else echo "FAIL  longer name (got $rc)"; fails=$((fails + 1)); fi
printf 'DIRC\0\0\0\4\0\0\0\0' > "$PROJECT/.git/index"
git_tracks .env; rc=$?
if [ "$rc" -eq 2 ]; then echo "ok    a v4 index is uncertain"; else echo "FAIL  v4 index (got $rc)"; fails=$((fails + 1)); fi

echo
if [ "$fails" -eq 0 ]; then echo "All checks passed."; else echo "$fails check(s) failed."; fi
[ "$fails" -eq 0 ]
