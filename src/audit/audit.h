/*
 * audit.h — HMAC-Chained Tamper-Evident Audit Log
 *
 * Every significant event in the gateway — handshake start/complete,
 * key exchange, auth success/failure, error, shutdown — is written here.
 *
 * Chain formula:
 *   record_hmac[n] = HMAC-SHA3-256(
 *       key  = audit_key,
 *       data = record_hmac[n-1] || seq_n || timestamp_n || layer_n || message_n
 *   )
 *
 * The genesis record (n=0) uses a zero-filled previous HMAC.
 * Guarantees:
 *   a) Any deleted record breaks the chain from that point forward.
 *   b) Any modified record breaks its own HMAC and all subsequent ones.
 *   c) A forger without the HMAC key cannot produce valid chain links.
 *
 * Thread safety: All public functions are thread-safe (internal mutex).
 *
 * Authors: Ojas Sharma & Anant Tripathi — SRM University
 */

#ifndef PQC_AUDIT_H
#define PQC_AUDIT_H

#include <stdint.h>
#include <stddef.h>

/* HMAC-SHA-256 output length */
#define AUDIT_HMAC_LEN      32

/* Maximum event message length */
#define AUDIT_MSG_MAX        512

/* ── Event Types ──────────────────────────────────────────────────────────── */
typedef enum {
    EVT_STARTUP         = 1,
    EVT_HANDSHAKE_START = 2,
    EVT_KEY_EXCHANGE    = 3,
    EVT_AUTH_OK         = 4,
    EVT_AUTH_FAIL       = 5,
    EVT_ERROR           = 6,
    EVT_SHUTDOWN        = 7,
} audit_event_t;

/* ── Severity Levels ──────────────────────────────────────────────────────── */
typedef enum {
    AUDIT_SEV_INFO     = 0,
    AUDIT_SEV_WARN     = 1,
    AUDIT_SEV_ERROR    = 2,
    AUDIT_SEV_CRITICAL = 3,
} audit_severity_t;

/* ── On-Disk Record Format ────────────────────────────────────────────────── */
/*
 * Binary-serialized, then hex-dumped to file.
 * Packed to prevent padding variance across architectures.
 */
typedef struct __attribute__((packed)) {
    uint64_t  timestamp_ms;              /* Unix epoch milliseconds          */
    uint32_t  event_type;                /* audit_event_t                    */
    uint8_t   layer;                     /* 0=system, 1=IPsec, 2=TLS, 3=SSH */
    uint32_t  payload_len;               /* actual message bytes             */
    char      payload[AUDIT_MSG_MAX];    /* human-readable event description */
    uint8_t   prev_hmac[AUDIT_HMAC_LEN]; /* HMAC of previous entry          */
    uint8_t   this_hmac[AUDIT_HMAC_LEN]; /* HMAC of this entry              */
} AuditRecord;

/* Opaque log context — one per process */
typedef struct AuditLog AuditLog;

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

/*
 * audit_init() — initialize the audit subsystem.
 *   log_path — path to the binary log file (created if absent).
 *   hmac_key — raw key bytes for HMAC-SHA3-256 (32 bytes).
 *   key_len  — must be 32.
 *
 * The HMAC key is copied into a secure buffer immediately.
 * Returns: AuditLog* on success, NULL on failure.
 */
AuditLog *audit_init(const char *log_path,
                     const uint8_t *hmac_key,
                     size_t key_len);

/*
 * audit_write() — append a new chained record.
 * Returns: 0 on success, -1 on failure.
 */
int audit_write(audit_event_t evt,
                uint8_t layer,
                const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/*
 * audit_verify_chain() — replay the entire log and verify HMAC chain.
 * Returns: 0 if chain intact, -1 if tampering detected.
 */
int audit_verify_chain(const char *log_path,
                       const uint8_t *hmac_key,
                       size_t key_len);

/*
 * audit_close() — flush, close file, scrub HMAC key.
 */
void audit_close(void);

/* ── Convenience Macros ───────────────────────────────────────────────────── */
#define AUDIT_INFO(layer, ...)    audit_write(EVT_STARTUP,         (layer), __VA_ARGS__)
#define AUDIT_HANDSHAKE(layer, ...) audit_write(EVT_HANDSHAKE_START, (layer), __VA_ARGS__)
#define AUDIT_KEYEX(layer, ...)   audit_write(EVT_KEY_EXCHANGE,    (layer), __VA_ARGS__)
#define AUDIT_AUTH_OK(layer, ...) audit_write(EVT_AUTH_OK,          (layer), __VA_ARGS__)
#define AUDIT_AUTH_FAIL(layer, ...) audit_write(EVT_AUTH_FAIL,      (layer), __VA_ARGS__)
#define AUDIT_ERROR(layer, ...)   audit_write(EVT_ERROR,           (layer), __VA_ARGS__)

#endif /* PQC_AUDIT_H */
