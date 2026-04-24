/*
 * gateway.h — PQC Trinity Gateway: Shared Types & Configuration
 *
 * Central header included by all modules. Defines:
 *   - Gateway configuration struct (parsed from gateway.conf)
 *   - Protocol layer constants
 *   - Shared status codes
 *   - Version string
 *
 * Authors: Ojas Sharma & Anant Tripathi — SRM University
 * FIPS 203 ML-KEM-768 | FIPS 204 ML-DSA-65
 */

#ifndef PQC_GATEWAY_H
#define PQC_GATEWAY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ---------------------------------------------------------------------------
 * Version & Identity
 * --------------------------------------------------------------------------- */
#define PQC_GW_NAME            "PQC Trinity Gateway"
#define PQC_GW_VERSION         "1.0.0"
#define PQC_GW_AUTHORS         "Ojas Sharma & Anant Tripathi"

/* ---------------------------------------------------------------------------
 * Protocol Layer Constants
 * --------------------------------------------------------------------------- */
#define LAYER_SYSTEM    0   /* gateway-level events */
#define LAYER_IPSEC     1   /* Layer 1 — Network (IKEv2 + ESP) */
#define LAYER_TLS       2   /* Layer 2 — Transport (TLS 1.3) */
#define LAYER_SSH       3   /* Layer 3 — Management (SSH 2.0) */

/* ---------------------------------------------------------------------------
 * Default Ports
 * --------------------------------------------------------------------------- */
#define DEFAULT_TLS_PORT      8443
#define DEFAULT_SSH_PORT      2222
#define DEFAULT_SSH_LEGACY    22

/* ---------------------------------------------------------------------------
 * PQC Algorithm Constants (FIPS 203 / FIPS 204)
 * --------------------------------------------------------------------------- */

/* ML-KEM-768 (FIPS 203) — Key Encapsulation */
#define MLKEM768_PK_BYTES       1184
#define MLKEM768_SK_BYTES       2400
#define MLKEM768_CT_BYTES       1088
#define MLKEM768_SS_BYTES       32

/* ML-DSA-65 (FIPS 204) — Digital Signatures */
#define MLDSA65_PK_BYTES        1952
#define MLDSA65_SK_BYTES        4032
#define MLDSA65_SIG_BYTES       3309

/* Hybrid X25519 + ML-KEM-768 */
#define HYBRID_SS_BYTES         32
#define X25519_SCALAR_BYTES     32
#define X25519_POINT_BYTES      32

/* TLS group name for hybrid PQC key exchange */
#define PQC_TLS_GROUP           "X25519MLKEM768"

/* FIPS 204 context strings per protocol */
#define PQC_CTX_IKEV2_AUTH      "IKEv2-AUTH-2026"
#define PQC_CTX_TLS_CERT        "TLS-CertificateVerify-2026"
#define PQC_CTX_SSH_HOSTKEY     "SSH-HostKey-2026"

/* ---------------------------------------------------------------------------
 * Gateway Configuration (parsed from gateway.conf)
 * --------------------------------------------------------------------------- */
typedef struct {
    /* Networking */
    uint16_t    tls_port;               /* TLS 1.3 server port (default 8443) */
    uint16_t    ssh_port;               /* PQC SSH port (default 2222) */

    /* File paths */
    char        tls_cert_path[256];     /* PEM certificate */
    char        tls_key_path[256];      /* PEM private key */
    char        ssh_hostkey_path[256];  /* ML-DSA-65 host key */
    char        ssh_hostkey_pub[256];   /* ML-DSA-65 public key */
    char        audit_log_path[256];    /* HMAC-chained audit log */
    char        config_dir[256];        /* /etc/pqc-gateway/ */

    /* Security */
    char        runtime_user[64];       /* user to drop privileges to */
    uint8_t     master_secret[32];      /* HMAC key derivation seed */
    bool        verbose;                /* human-readable stderr output */
} GatewayConfig;

/* ---------------------------------------------------------------------------
 * Status Codes
 * --------------------------------------------------------------------------- */
typedef enum {
    GW_OK       =  0,
    GW_ERROR    = -1,
    GW_EPERM    = -2,   /* permission error */
    GW_ECONFIG  = -3,   /* config parse error */
    GW_ECRYPTO  = -4,   /* cryptographic failure */
} gw_status_t;

/* ---------------------------------------------------------------------------
 * Global shutdown flag (set by signal handler)
 * --------------------------------------------------------------------------- */
#include <signal.h>
extern volatile sig_atomic_t g_shutdown;

/* ---------------------------------------------------------------------------
 * Config loader (implemented in main.c)
 * --------------------------------------------------------------------------- */
int gateway_config_load(GatewayConfig *cfg, const char *path);
void gateway_config_defaults(GatewayConfig *cfg);

#endif /* PQC_GATEWAY_H */
