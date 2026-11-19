#!/usr/bin/env bash
#
# mayhem/test.sh — runs upstream's gtest suite that mayhem/build.sh built (normal flags) in build/tests:
# unit (DNS utils, hex, PSKc known answers, task runner, ...), REST (JSON encoders, network-diagnostic
# handler on OpenThread's fake platform), SRP advertising proxy, DNS-SD platform, NCP host API, firewall
# manager with the nftables backend and monitor (OTBR_NFTABLES=ON, as upstream's nftables-check job),
# RCP host API (RcpHost on OpenThread's fake platform), web service (OTBR_WEB) and telemetry
# (OTBR_TELEMETRY_DATA_API), plus upstream's two tool ctests (tests/tools/test-pskc and test-steering-data,
# known-answer checks of the pskc/steering-data tools).
# This is everything upstream's unprivileged CI runs (script/test `check`: ctest -LE sudo; build.yml
# nftables-check) that this configuration registers (OTBR_REST, OTBR_WEB, OTBR_TELEMETRY_DATA_API,
# OTBR_NFTABLES, default OTBR_MDNS=openthread) except:
#   - otbr-posix-gtest-unit: upstream labels it `sudo` (it creates tun/netlink interfaces); upstream's
#     own unprivileged run is `ctest -LE sudo` (script/test).
#   - tests/rest: labelled TESTREST; it needs a running otbr-agent plus an ot-rcp simulator.
#   - Logging.* (5 tests in otbr-gtest-unit): they assert on lines written to the host's syslog, which a
#     container does not have.
# gtest and the tool scripts assert values (EXPECT_EQ / string compare on known outputs), so a neutered
# program fails here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Each suite must report at least one passing test; a binary that crashes or runs nothing is a failure.
SUITES="otbr-gtest-unit otbr-gtest-rest otbr-gtest-advertising-proxy otbr-gtest-unit-dnssd otbr-gtest-ncp-host-api
        otbr-gtest-firewall otbr-gtest-host-api otbr-gtest-web otbr-gtest-telemetry"
passed=0 failed=0 skipped=0
log="$(mktemp)"
for suite in $SUITES; do
  bin="build/tests/tests/gtest/$suite"
  if [ ! -x "$bin" ]; then
    echo "missing $bin — mayhem/build.sh should have built it" >&2
    failed=$((failed + 1)); continue
  fi
  "$bin" --gtest_filter='-Logging.*' --gtest_brief=0 >"$log" 2>&1
  rc=$?
  p=$(grep -cE '^\[       OK \]' "$log")
  f=$(grep -cE '^\[  FAILED  \] [A-Za-z0-9_/]+\.[A-Za-z0-9_/]+ \(' "$log")
  s=$(grep -cE '^\[  SKIPPED \] [A-Za-z0-9_/]+\.' "$log")
  # A run that crashed or reported nothing counts as a failure of the whole binary.
  if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then f=1; fi
  if [ "$p" -eq 0 ] && [ "$f" -eq 0 ]; then f=1; fi
  if ! grep -qE '^\[  PASSED  \] [0-9]+ test' "$log" && [ "$f" -eq 0 ]; then f=1; fi
  echo "$suite: passed=$p failed=$f skipped=$s (rc=$rc)"
  [ "$f" -eq 0 ] || tail -40 "$log"
  passed=$((passed + p)); failed=$((failed + f)); skipped=$((skipped + s))
done

# Upstream's tool ctests (tests/tools/CMakeLists.txt): each script runs its tool via $OTBR_COMPUTER and
# compares the output with a known answer; it exits non-zero on a mismatch.
for tool in pskc steering-data; do
  bin="$SRC/build/tests/tools/$tool"
  if [ ! -x "$bin" ]; then
    echo "missing $bin — mayhem/build.sh should have built it" >&2
    failed=$((failed + 1)); continue
  fi
  if OTBR_COMPUTER="$bin" bash "tests/tools/test-$tool" >"$log" 2>&1; then
    echo "tool $tool: passed"; passed=$((passed + 1))
  else
    echo "tool $tool: FAILED"; tail -20 "$log"; failed=$((failed + 1))
  fi
done
rm -f "$log"
emit_ctrf "gtest" "$passed" "$failed" "$skipped"
