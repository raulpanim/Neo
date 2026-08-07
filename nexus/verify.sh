#!/usr/bin/env bash
# Exercises every endpoint against a running API. Reports, never fixes.
BASE="${1:-http://localhost:3000}"
pass=0; fail=0

check() {
  local label="$1" path="$2" method="${3:-GET}" body="${4:-}" expect="${5:-2xx}"
  local code
  if [ "$method" = "POST" ]; then
    code=$(curl -s -o /tmp/nexus_out -w '%{http_code}' -X POST "$BASE$path" \
      -H 'content-type: application/json' -d "${body:-{\}}")
  else
    code=$(curl -s -o /tmp/nexus_out -w '%{http_code}' "$BASE$path")
  fi
  local ok=0
  if [ "$expect" = "2xx" ]; then
    [ "$code" -ge 200 ] && [ "$code" -lt 300 ] && ok=1
  else
    [ "$code" = "$expect" ] && ok=1
  fi
  if [ "$ok" -eq 1 ]; then
    printf '\033[0;32mok  \033[0m %-42s %s\n' "$label" "$code"; pass=$((pass+1))
  else
    printf '\033[0;31mFAIL\033[0m %-42s %s (expected %s)\n' "$label" "$code" "$expect"
    head -c 300 /tmp/nexus_out; echo; fail=$((fail+1))
  fi
}

echo "Checking $BASE"
check "health"                  "/api/health"
check "graph stats"             "/api/graph/stats"
check "search"                  "/api/graph/search?q=example"
check "attack surface"          "/api/graph/attack-surface/example.com"
check "vulnerabilities"         "/api/vulnerabilities/domain/example.com"
check "exploitable"             "/api/vulnerabilities/exploitable"
check "inferred chains"         "/api/analysis/chains"
check "recorded chains"         "/api/analysis/chains/recorded"
check "reliability matrix"      "/api/intel/sources"
check "conflicts"               "/api/intel/conflicts"
check "collector status"        "/api/sources/status"
check "trending"                "/api/sources/trending"
check "unknown domain is 404"   "/api/graph/attack-surface/nope.invalid" GET "" 404

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
