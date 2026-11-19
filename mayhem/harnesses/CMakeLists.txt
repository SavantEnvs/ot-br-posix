# Fuzz harness build for ot-br-posix (mayhem layer). Wraps upstream's own CMake project so the harnesses
# link upstream's real library targets (otbr-*, openthread-*, mbedtls, cjson), all compiled with the
# sanitizer/coverage flags mayhem/build.sh passes in CMAKE_C_FLAGS/CMAKE_CXX_FLAGS.
cmake_minimum_required(VERSION 3.14)
project(otbr-mayhem-fuzz C CXX)

set(OTBR_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(OT_ROOT ${OTBR_ROOT}/third_party/openthread/repo)

# Upstream's top-level project (its tests are skipped: CMAKE_PROJECT_NAME is not upstream's).
add_subdirectory(${OTBR_ROOT} otbr)

if(NOT DEFINED FUZZ_ENGINE OR NOT DEFINED STANDALONE_MAIN_OBJ OR NOT DEFINED FUZZ_OUT_DIR)
    message(FATAL_ERROR "set -DFUZZ_ENGINE=<libFuzzer link flag> -DSTANDALONE_MAIN_OBJ=<driver .o> -DFUZZ_OUT_DIR=<dir>")
endif()

if(NOT DEFINED LSAN_OFF)
    message(FATAL_ERROR "set -DLSAN_OFF=<path to mayhem/lsan_off.cc>")
endif()

# OpenThread's fake platform + upstream's fake posix platform: what upstream's REST/host gtests run on.
add_library(otbr-fuzz-fakeplat OBJECT
    ${OT_ROOT}/tests/gtest/fake_platform.cpp
    ${OTBR_ROOT}/tests/gtest/fake_posix_platform.cpp
)
target_include_directories(otbr-fuzz-fakeplat PUBLIC
    ${OTBR_ROOT}/src
    ${OT_ROOT}/src/core
    ${OT_ROOT}/tests/gtest
)
target_link_libraries(otbr-fuzz-fakeplat PUBLIC otbr-config openthread-ftd openthread-posix mbedtls)
target_compile_options(otbr-fuzz-fakeplat PRIVATE -Wno-error)

# Each harness is linked twice: with libFuzzer (the Mayhem target) and with the run-once standalone
# driver (<name>-standalone, a reproducer without the libFuzzer runtime).
add_custom_target(otbr-fuzzers)
function(otbr_fuzzer name)
    foreach(variant fuzz standalone)
        if(variant STREQUAL "fuzz")
            set(bin ${name})
            set(engine ${FUZZ_ENGINE})
        else()
            set(bin ${name}-standalone)
            set(engine ${STANDALONE_MAIN_OBJ})
        endif()
        add_executable(${bin} ${name}.cpp ${LSAN_OFF})
        target_include_directories(${bin} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${OTBR_ROOT}/include
            ${OTBR_ROOT}/src
            ${OT_ROOT}/include
            ${OT_ROOT}/src/core
            ${OT_ROOT}/tests/gtest
            ${OTBR_ROOT}/third_party/cJSON/repo
            ${OTBR_ROOT}/third_party/cpp-httplib/repo
        )
        target_compile_options(${bin} PRIVATE -Wno-error)
        target_link_libraries(${bin} PRIVATE ${ARGN} ${engine})
        set_target_properties(${bin} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${FUZZ_OUT_DIR})
        add_dependencies(otbr-fuzzers ${bin})
    endforeach()
endfunction()

otbr_fuzzer(fuzz_dns_utils otbr-utils otbr-common)
otbr_fuzzer(fuzz_pskc otbr-utils otbr-common mbedtls)
otbr_fuzzer(fuzz_mdns_txt otbr-mdns otbr-fuzz-fakeplat otbr-utils otbr-common)
otbr_fuzzer(fuzz_rest_json otbr-rest cjson otbr-fuzz-fakeplat otbr-utils otbr-common)
otbr_fuzzer(fuzz_rest_actions otbr-rest cjson otbr-fuzz-fakeplat otbr-host otbr-posix otbr-utils otbr-common
            openthread-ftd openthread-posix mbedtls pthread)
otbr_fuzzer(fuzz_rest_server otbr-rest cjson otbr-fuzz-fakeplat otbr-border-agent otbr-host otbr-posix otbr-utils otbr-common
            openthread-ftd openthread-posix mbedtls pthread)
otbr_fuzzer(fuzz_ncp_spinel otbr-host otbr-posix otbr-utils otbr-common openthread-ftd openthread-posix mbedtls pthread)
target_include_directories(fuzz_ncp_spinel PRIVATE ${OT_ROOT}/src)
target_include_directories(fuzz_ncp_spinel-standalone PRIVATE ${OT_ROOT}/src)
