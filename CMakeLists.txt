cmake_minimum_required(VERSION 3.22)
project(pqc_trinity_gateway
    VERSION 1.0.0
    DESCRIPTION "PQC Trinity Gateway — 3-Layer Post-Quantum Secure Gateway"
    LANGUAGES C
)

# ── Language standard ─────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Build type ────────────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# ── Dependencies ──────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# OpenSSL >= 3.0 (3.2+ recommended for oqs-provider PQC groups)
find_package(OpenSSL 3.0 REQUIRED)

# liboqs — NIST FIPS 203/204 algorithms
pkg_check_modules(LIBOQS REQUIRED liboqs>=0.10.0)

# libssh — SSHv2 server API
pkg_check_modules(LIBSSH libssh>=0.10.0)

# ── Compiler hardening flags ──────────────────────────────────────────────────
# Defense-in-depth per NIST SP 800-218 SSDF
set(HARDENING_FLAGS
    -fstack-protector-strong        # Stack canaries
    -fstack-clash-protection        # Prevent stack-to-heap pivots
    -fcf-protection=full            # Forward-edge CFI (CET)
    -D_FORTIFY_SOURCE=2             # Bounds-checked libc wrappers
    -ffunction-sections
    -fdata-sections
    -Wall -Wextra -Werror
    -Wformat=2 -Wformat-security
    -Wnull-dereference
    -Wvla                           # No VLAs — deterministic stack
    -Wshadow
    -fwrapv                         # Signed overflow wraps
    -fno-common
    -fPIE
)

set(HARDENING_LINK_FLAGS
    -pie                            # ASLR
    -Wl,-z,relro                    # Full RELRO
    -Wl,-z,now
    -Wl,-z,noexecstack              # NX stack
    -Wl,--gc-sections
    -Wl,-rpath,/usr/local/lib
    -Wl,-rpath,/usr/local/ossl-pqc/lib64
)

# ── Source files ──────────────────────────────────────────────────────────────
set(GATEWAY_SOURCES
    src/main.c
    src/vault/vault.c
    src/audit/audit.c
    src/layer1_ipsec/ipsec_manager.c
    src/layer2_tls/tls_server.c
    src/layer3_ssh/ssh_server.c
)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(pqc-gateway ${GATEWAY_SOURCES})

target_include_directories(pqc-gateway PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${LIBOQS_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

if(LIBSSH_FOUND)
    target_include_directories(pqc-gateway PRIVATE ${LIBSSH_INCLUDE_DIRS})
endif()

target_compile_options(pqc-gateway PRIVATE ${HARDENING_FLAGS})

target_compile_definitions(pqc-gateway PRIVATE
    _POSIX_C_SOURCE=200809L
    _GNU_SOURCE
    PQC_GW_VERSION="${PROJECT_VERSION}"
)

target_link_libraries(pqc-gateway PRIVATE
    OpenSSL::Crypto
    OpenSSL::SSL
    ${LIBOQS_LIBRARIES}
    Threads::Threads
)

if(LIBSSH_FOUND)
    target_link_libraries(pqc-gateway PRIVATE ${LIBSSH_LIBRARIES})
else()
    message(WARNING "libssh not found — SSH layer will not compile")
endif()

target_link_options(pqc-gateway PRIVATE ${HARDENING_LINK_FLAGS})

# ── Installation ──────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS pqc-gateway RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

# ── Summary ───────────────────────────────────────────────────────────────────
message(STATUS "══════════════════════════════════════════════════════")
message(STATUS "  PQC Trinity Gateway v${PROJECT_VERSION}")
message(STATUS "  Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "  OpenSSL     : ${OPENSSL_VERSION}")
message(STATUS "  liboqs      : ${LIBOQS_VERSION}")
message(STATUS "  libssh      : ${LIBSSH_VERSION}")
message(STATUS "  Hardening   : PIE, RELRO, NX, SSP, CFI")
message(STATUS "══════════════════════════════════════════════════════")
