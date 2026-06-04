#!/bin/bash
# scripts/code_review.sh — run before handing to QA
DIR=${1:-datanexus}
FAIL=0
echo "=== DataNexus Code Review === $(date -u +%FT%TZ)"

echo "--- [1/6] Secrets scan"
detect-secrets scan $DIR --baseline .secrets.baseline --only-allowlisted || FAIL=1

echo "--- [2/6] Bandit security lint"
bandit -r $DIR -ll -q || FAIL=1

echo "--- [3/6] Forbidden patterns"
for p in "lru_cache" "import psycopg2" "from psycopg2"; do
  grep -rn "$p" $DIR && { echo "FAIL: $p found"; FAIL=1; } || true
done

echo "--- [4/6] Required patterns in handlers"
for f in $(grep -rl "@.*\.tool()" $DIR 2>/dev/null); do
  for req in "AuditContext" "standard_response_fields" "with_timeout"; do
    grep -q "$req" "$f" || { echo "FAIL: $f missing $req"; FAIL=1; }
  done
done

echo "--- [5/6] No hardcoded Redis keys"
grep -rn '"fb:' $DIR | grep -v "config.py\|#\|key_" && FAIL=1 || true

echo "--- [6/6] Ruff lint"
ruff check $DIR --quiet || FAIL=1

echo ""
[ $FAIL -eq 0 ] && echo "CODE REVIEW: PASS" || { echo "CODE REVIEW: FAIL"; exit 1; }
