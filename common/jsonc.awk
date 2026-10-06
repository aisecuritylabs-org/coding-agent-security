# jsonc.awk: convert JSON with comments (VS Code-style settings.json) to JSON.
# Removes // and /* */ comments and trailing commas outside strings, leaving
# string contents untouched. Linear time: kept text is copied in segments.
# Usage: awk -f jsonc.awk settings.json | jq .

{ buf = buf $0 "\n" }

END {
  n = length(buf)
  out = ""; seg = 1; ins = 0; esc = 0; i = 1
  # Pass 1: drop comments.
  while (i <= n) {
    c = substr(buf, i, 1)
    if (ins) {
      if (esc) esc = 0
      else if (c == "\\") esc = 1
      else if (c == "\"") ins = 0
      i++; continue
    }
    if (c == "\"") { ins = 1; i++; continue }
    if (c == "/") {
      d = substr(buf, i + 1, 1)
      if (d == "/") {
        out = out substr(buf, seg, i - seg)
        while (i <= n && substr(buf, i, 1) != "\n") i++
        seg = i; continue
      }
      if (d == "*") {
        # A comment separates tokens, so it becomes a space: 1/*x*/2 stays two
        # tokens and is rejected by jq instead of becoming 12.
        out = out substr(buf, seg, i - seg) " "
        i += 2
        while (i <= n && !(substr(buf, i, 1) == "*" && substr(buf, i + 1, 1) == "/")) i++
        if (i > n) { bad = 1; break }   # unterminated comment: invalid input
        i += 2; seg = i; continue
      }
    }
    i++
  }
  if (bad) exit 1
  out = out substr(buf, seg)

  # Pass 2: drop trailing commas before } or ].
  n = length(out); res = ""; seg = 1; ins = 0; esc = 0
  for (i = 1; i <= n; i++) {
    c = substr(out, i, 1)
    if (ins) {
      if (esc) esc = 0
      else if (c == "\\") esc = 1
      else if (c == "\"") ins = 0
      continue
    }
    if (c == "\"") { ins = 1; continue }
    if (c == ",") {
      j = i + 1
      while (j <= n && index(" \t\r\n", substr(out, j, 1)) > 0) j++
      t = substr(out, j, 1)
      if (t == "}" || t == "]") { res = res substr(out, seg, i - seg); seg = i + 1 }
    }
  }
  printf "%s", res substr(out, seg)
}
