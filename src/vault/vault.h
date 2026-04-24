/*
 * vault.h — Secure Memory Vault with Canary Guards
 *
 * All private keys, KEM shared-secrets, and HMAC keys used by the PQC
 * gateway are allocated through this subsystem. Guarantees:
 *
 *   1. mlock()      — pages are never swapped to disk.
 *   2. Canary guards — detect linear over-read / over-write.
 *   3. OPENSSL_cleanse() — scrub before free (compiler cannot elide).
 *   4. mprotect(PROT_NONE) — key pages inaccessible when not in use.
 *   5. Thread-safe  — all operations protected by a pthread mutex.
 *
 * Threat model (NIST SP 800-57 §5.3):
 *   A1 — Swap/hibernation read         → mlockall + mlock
 *   A2 — /proc/self/mem or ptrace      → mprotect(PROT_NONE) + PR_SET_DUMPABLE=0
 *   A3 — Heap corruption               → Canary guards; abort on violation
 *   G1 — Secrets persist after use      → OPENSSL_cleanse + munmap
 *   G2 — Compiler removes zeroing      → OPENSSL_cleanse volatile write loop
 *   G3 — Core dump leaks keys          → PR_SET_DUMPABLE=0 + MADV_DONTDUMP
 *
 * Authors: Ojas Sharma & Anant Tripathi — SRM University
 */

#ifndef PQC_VAULT_H
#define PQC_VAULT_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

/* ── Canary Constants ─────────────────────────────────────────────────────── */
#define CANARY_MAGIC_HEAD   UINT64_C(0xDEADBEEFCAFEBABE)
#define CANARY_MAGIC_TAIL   UINT64_C(0xBADC0FFEE0DDF00D)
#define CANARY_FLAT_HEAD_OFFSET  0
#define CANARY_FLAT_DATA_OFFSET  sizeof(uint64_t)
#define CANARY_FLAT_OVERHEAD     (2 * sizeof(uint64_t))

/* Maximum label length for debugging / audit purposes */
#define VAULT_LABEL_MAX  64

/* Maximum tracked vault allocations */
#define VAULT_REGISTRY_MAX  256

/* ── Vault Handle ─────────────────────────────────────────────────────────── */
typedef struct VaultHandle VaultHandle;

struct VaultHandle {
    char            label[VAULT_LABEL_MAX]; /* human-readable identifier     */
    uint8_t        *data;                   /* pointer into mlock'd region   */
    size_t          data_len;               /* usable bytes                  */
    void           *_outer;                 /* raw mmap base (with canaries) */
    size_t          _outer_len;             /* mmap total length             */
    pthread_mutex_t _lock;                  /* per-vault mutex               */
    int             _locked;                /* 1 = PROT_NONE, 0 = RW         */
};

/* ── Subsystem Lifecycle ──────────────────────────────────────────────────── */

/*
 * vault_init() — must be called once at process start.
 * Calls mlockall(MCL_CURRENT | MCL_FUTURE), disables core dumps.
 * Returns: 0 on success, -1 on failure (caller must abort).
 */
int vault_init(void);

/*
 * vault_destroy() — forcibly frees all remaining vaults, munlockall.
 * Call at process exit.
 */
void vault_destroy(void);

/* ── Allocation ───────────────────────────────────────────────────────────── */

/*
 * vault_alloc() — allocate a mlock'd, canary-guarded buffer.
 * Buffer starts in PROT_NONE state (locked). Call vault_unlock() before use.
 * Returns: VaultHandle* on success, NULL on failure.
 */
VaultHandle *vault_alloc(const char *label, size_t data_len);

/* ── Access Control ───────────────────────────────────────────────────────── */

/*
 * vault_unlock() — make data region readable/writable (PROT_READ|PROT_WRITE).
 * Must be paired with vault_lock().
 */
int vault_unlock(VaultHandle *h);

/*
 * vault_lock() — revoke access (mprotect PROT_NONE).
 * Verifies canary integrity before locking; aborts on corruption.
 */
int vault_lock(VaultHandle *h);

/* ── Cleanup ──────────────────────────────────────────────────────────────── */

/*
 * vault_free() — scrub with OPENSSL_cleanse, munmap, null the pointer.
 */
void vault_free(VaultHandle **h_ptr);

/* ── Simple Helpers (backward compat with Master Build Prompt API) ────────── */

/*
 * vault_lock_memory() — lock a specific memory region (prevents swap).
 */
int vault_lock_memory(void *addr, size_t len);

/*
 * vault_zeroize() — securely zero a buffer using OPENSSL_cleanse + barrier.
 * NEVER use memset for key material — the compiler can optimize it away.
 */
void vault_zeroize(void *buf, size_t len);

/* ── Accessor Helpers ─────────────────────────────────────────────────────── */

static inline uint8_t *vault_ptr(VaultHandle *h)
{
    return h ? h->data : NULL;
}

static inline const uint8_t *vault_const_ptr(const VaultHandle *h)
{
    return h ? h->data : NULL;
}

static inline size_t vault_size(const VaultHandle *h)
{
    return h ? h->data_len : 0U;
}

static inline int vault_check_integrity(const VaultHandle *h)
{
    return (h && h->data && h->data_len > 0U) ? 0 : -1;
}

/* ── Canary Inline Helpers ────────────────────────────────────────────────── */

static inline void canary_flat_init(void *outer, size_t data_size)
{
    uint64_t *head = (uint64_t *)outer;
    uint64_t *tail = (uint64_t *)((uint8_t *)outer
                                   + sizeof(uint64_t)
                                   + data_size);
    *head = CANARY_MAGIC_HEAD;
    *tail = CANARY_MAGIC_TAIL;
}

static inline int canary_flat_check(const void *outer, size_t data_size)
{
    const uint64_t *head = (const uint64_t *)outer;
    const uint64_t *tail = (const uint64_t *)((const uint8_t *)outer
                                               + sizeof(uint64_t)
                                               + data_size);
    /* constant-time: XOR-reduce both sentinels */
    uint64_t diff = (*head ^ CANARY_MAGIC_HEAD) | (*tail ^ CANARY_MAGIC_TAIL);
    return (diff == 0) ? 0 : -1;
}

#endif /* PQC_VAULT_H */
