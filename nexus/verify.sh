#!/usr/bin/env bash
# Hits the nexus API's endpoints and reports status codes + error bodies.
# Every check must reach 2xx except nope.invalid, which must 404.
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:3000}"
FAILURES=0

check() {
  local path="$1" expect_status="$2"
  local body_file status
  body_file="$(mktemp)"
  status="$(curl -s -o "$body_file" -w '%{http_code}' "${BASE_URL}${path}")"

  local ok=0
  if [[ "$expect_status" == "2xx" ]]; then
    [[ "$status" =~ ^2[0-9][0-9]$ ]] && ok=1
  else
    [[ "$status" == "$expect_status" ]] && ok=1
  fi

  if [[ "$ok" -eq 1 ]]; then
    printf '[PASS] %-45s -> %s\n' "$path" "$status"
  else
    printf '[FAIL] %-45s -> %s (expected %s)\n' "$path" "$status" "$expect_status"
    echo "       body: $(cat "$body_file")"
    FAILURES=$((FAILURES + 1))
  fi
  rm -f "$body_file"
}

echo "==> Verifying nexus API at ${BASE_URL}"
check /health 2xx
check /api/domains 2xx
check /api/domains/example.com 2xx
check /api/hosts 2xx
check /api/hosts/93.184.216.34 2xx
check /api/cves 2xx
check /api/cves/CVE-2021-44228 2xx
check /api/vulnerabilities/domain/example.com 2xx
check /api/analysis/chains 2xx
check /api/intel/conflicts 2xx
check /api/intel/timeline/cve/CVE-2022-1234 2xx
check /api/graph 2xx
check /nope.invalid 404

echo
if [[ "$FAILURES" -eq 0 ]]; then
  echo "All 13 checks passed."
  exit 0
else
  echo "${FAILURES} check(s) failed."
  exit 1
fi
