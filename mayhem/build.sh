#!/usr/bin/env bash
#
# mayhem/build.sh — builds ot-br-posix's fuzz harnesses and its gtest suite.
#
# Runs in the commit image as `mayhem` in /mayhem (SRC). Uses the base image's build contract
# (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/DEBUG_FLAGS/STANDALONE_FUZZ_MAIN). Everything it needs is
# in the tree (git submodules: openthread + mbedtls, cJSON, cpp-httplib) or in apt packages installed
# by mayhem/Dockerfile, so it runs offline and re-runs incrementally.
#
#   1) build/tests — upstream's gtest binaries, NORMAL flags (the functional oracle mayhem/test.sh runs)
#   2) build/fuzz  — mayhem/harnesses/CMakeLists.txt wraps upstream's CMake project, so the harnesses link
#                    upstream's real library targets, all compiled with $SANITIZER_FLAGS $DEBUG_FLAGS and
#                    SanitizerCoverage; each harness is linked with libFuzzer (/mayhem/<name>) and with the
#                    standalone run-once driver (/mayhem/<name>-standalone).
# Both build dirs are under build/, which upstream's .gitignore already ignores.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export CC CXX

cd "$SRC"

# Upstream's build is CMake + ninja; the submodules are vendored in the checkout (actions/checkout
# fetches them recursively). cJSON's own CMakeLists predates CMake 3.5 policies.
COMMON_CMAKE=(-GNinja -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DOTBR_REST=ON -DOTBR_VERSION=mayhem)

# 1) The functional suite (upstream gtests), normal flags. The options add the suites upstream's CI runs
#    without privileges: OTBR_WEB + OTBR_TELEMETRY_DATA_API from script/test's `check` build
#    (otbr-gtest-web, otbr-gtest-telemetry) and OTBR_NFTABLES=ON OT_FIREWALL=OFF from build.yml's
#    nftables-check job (the nftables tests in otbr-gtest-firewall). Only test targets are built, so the
#    web GUI's npm frontend is not needed. Upstream's CI compiles with GCC; the nftables sources use VLAs,
#    which clang flags with -Wvla-cxx-extension and upstream's -Werror turns fatal, so only that warning
#    stays a warning.
cmake -S . -B build/tests "${COMMON_CMAKE[@]}" \
    -DOTBR_WEB=ON -DOTBR_TELEMETRY_DATA_API=ON -DOTBR_NFTABLES=ON -DOT_FIREWALL=OFF \
    -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS -Wno-error=vla-cxx-extension" \
    -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build build/tests -j"$MAYHEM_JOBS" --target \
    otbr-gtest-unit otbr-gtest-rest otbr-gtest-advertising-proxy otbr-gtest-unit-dnssd otbr-gtest-ncp-host-api \
    otbr-gtest-firewall otbr-gtest-host-api otbr-gtest-web otbr-gtest-telemetry pskc steering-data

# 2) The fuzz harnesses. The standalone driver is C: compile it as a C object so its
#    LLVMFuzzerTestOneInput reference keeps C linkage.
mkdir -p build/fuzz
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/fuzz/standalone_main.o
# -Wno-error: upstream adds -Werror and clang's sanitizer builds warn where upstream's CI compilers
# do not; warnings stay visible. -O1 keeps the instrumented OpenThread core fast enough to fuzz.
# Every harness also links mayhem/lsan_off.cc (see LSAN_OFF below).
FUZZ_FLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -Wno-error"
# UBSan `enum` is relaxed (the rest of UBSan and ASan stay halting): OpenThread's spinel helper casts every
# out-of-range spinel status to otError (src/lib/spinel/spinel_helper.cpp SpinelStatusToOtError), which the
# first status frame of every NCP input trips. Only added when sanitizers are on.
[ -z "$SANITIZER_FLAGS" ] || FUZZ_FLAGS="$FUZZ_FLAGS -fno-sanitize=enum"
cmake -S mayhem/harnesses -B build/fuzz "${COMMON_CMAKE[@]}" \
    -DCMAKE_BUILD_TYPE=None \
    -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
    -DFUZZ_ENGINE="$LIB_FUZZING_ENGINE" \
    -DSTANDALONE_MAIN_OBJ="$SRC/build/fuzz/standalone_main.o" \
    -DFUZZ_OUT_DIR="$SRC" \
    -DLSAN_OFF="$SRC/mayhem/lsan_off.cc"  # __lsan_is_turned_off(): LeakSanitizer off, ASan/UBSan on
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target otbr-fuzzers
