/*
 * vault.c — Secure Memory Vault Implementation
 *
 * mlock-managed memory allocations with canary guards, mprotect access
 * control, and OPENSSL_cleanse scrubbing. See vault.h for full threat model.
 *
 * Authors: Ojas Sharma & Anant Tripathi — SRM University
 */

#include "vault.h"

#include <openssl/crypto.h>   /* OPENSSL_cleanse() */
#include <sys/mman.h>         /* mmap, mlock, mprotect, MADV_DONTDUMP */
#include <sys/resource.h>     /* setrlimit — RLIMIT_MEMLOCK */
#include <sys/prctl.h>        /* PR_SET_DUMPABLE */
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           /* sysconf _SC_PAGESIZE */

/* ── Internal Registry ────────────────────────────────────────────────────── */

static struct {
    VaultHandle     *entries[VAULT_REGISTRY_MAX];
    size_t           count;
    pthread_mutex_t  lock;
    int              initialised;
} g_registry = {
    .count       = 0,
    .initialised = 0,
    .lock        = PTHREAD_MUTEX_INITIALIZER,
};

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static size_t page_align_up(size_t n)
{
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    return ((n + (size_t)page - 1) / (size_t)page) * (size_t)page;
}

static int registry_add(VaultHandle *h)
{
    if (g_registry.count >= VAULT_REGISTRY_MAX) return -1;
    g_registry.entries[g_registry.count++] = h;
    return 0;
}

static void registry_remove(VaultHandle *h)
{
    pthread_mutex_lock(&g_registry.lock);
    for (size_t i = 0; i < g_registry.count; i++) {
        if (g_registry.entries[i] == h) {
            g_registry.entries[i] = g_registry.entries[--g_registry.count];
            g_registry.entries[g_registry.count] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&g_registry.lock);
}

/* ── vault_init ───────────────────────────────────────────────────────────── */

int vault_init(void)
{
    /* Raise RLIMIT_MEMLOCK as high as possible */
    struct rlimit rl;
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        (void)setrlimit(RLIMIT_MEMLOCK, &rl);
    }

    /*
     * mlockall(MCL_CURRENT | MCL_FUTURE):
     *   MCL_CURRENT — lock all pages currently mapped.
     *   MCL_FUTURE  — lock all pages mapped in the future.
     */
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        perror("vault_init: mlockall failed (need CAP_IPC_LOCK or root)");
        return -1;
    }

    /* Disable core dumps — secret pages must never reach disk */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        /* non-fatal */
    }

    /* Set RLIMIT_CORE to 0 for belt-and-suspenders */
    struct rlimit core_rl = { .rlim_cur = 0, .rlim_max = 0 };
    (void)setrlimit(RLIMIT_CORE, &core_rl);

    pthread_mutex_lock(&g_registry.lock);
    g_registry.initialised = 1;
    pthread_mutex_unlock(&g_registry.lock);

    return 0;
}

/* ── vault_alloc ──────────────────────────────────────────────────────────── */

VaultHandle *vault_alloc(const char *label, size_t data_len)
{
    if (!label || data_len == 0) {
        errno = EINVAL;
        return NULL;
    }

    /*
     * Memory layout (all page-aligned):
     *   [guard page | uint64_t head_canary | data | uint64_t tail_canary | guard page]
     */
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    size_t pg = (size_t)page_size;

    size_t inner_raw  = CANARY_FLAT_OVERHEAD + data_len;
    size_t inner_size = page_align_up(inner_raw);
    size_t total_size = pg + inner_size + pg;

    void *outer = mmap(NULL, total_size,
                       PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE,
                       -1, 0);
    if (outer == MAP_FAILED) return NULL;

    /* Exclude from core dumps */
    (void)madvise(outer, total_size, MADV_DONTDUMP);

    /* mlock the inner region */
    uint8_t *inner_base = (uint8_t *)outer + pg;
    if (mlock(inner_base, inner_size) != 0) {
        munmap(outer, total_size);
        return NULL;
    }

    /* Write canary sentinels */
    canary_flat_init(inner_base, data_len);

    /* Guard pages: PROT_NONE (tripwires for over-read/write) */
    if (mprotect(outer, pg, PROT_NONE) != 0 ||
        mprotect(inner_base + inner_size, pg, PROT_NONE) != 0) {
        munmap(outer, total_size);
        return NULL;
    }

    /* Allocate handle (non-secret metadata, normal heap) */
    VaultHandle *h = calloc(1, sizeof(VaultHandle));
    if (!h) {
        munmap(outer, total_size);
        return NULL;
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&h->_lock, &attr);
    pthread_mutexattr_destroy(&attr);

    snprintf(h->label, VAULT_LABEL_MAX, "%s", label);
    h->_outer     = outer;
    h->_outer_len = total_size;
    h->data       = inner_base + CANARY_FLAT_DATA_OFFSET;
    h->data_len   = data_len;
    h->_locked    = 1;

    /* Default state: locked (PROT_NONE) */
    if (mprotect(inner_base, inner_size, PROT_NONE) != 0) {
        free(h);
        munmap(outer, total_size);
        return NULL;
    }

    /* Register */
    pthread_mutex_lock(&g_registry.lock);
    if (registry_add(h) != 0) {
        pthread_mutex_unlock(&g_registry.lock);
        free(h);
        munmap(outer, total_size);
        return NULL;
    }
    pthread_mutex_unlock(&g_registry.lock);

    return h;
}

/* ── vault_unlock ─────────────────────────────────────────────────────────── */

int vault_unlock(VaultHandle *h)
{
    if (!h) return -1;
    pthread_mutex_lock(&h->_lock);

    if (!h->_locked) {
        pthread_mutex_unlock(&h->_lock);
        return 0;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    uint8_t *inner_base = (uint8_t *)h->_outer + (size_t)page_size;
    size_t   inner_size = page_align_up(CANARY_FLAT_OVERHEAD + h->data_len);

    if (mprotect(inner_base, inner_size, PROT_READ | PROT_WRITE) != 0) {
        pthread_mutex_unlock(&h->_lock);
        return -1;
    }

    h->_locked = 0;
    pthread_mutex_unlock(&h->_lock);
    return 0;
}

/* ── vault_lock ───────────────────────────────────────────────────────────── */

int vault_lock(VaultHandle *h)
{
    if (!h) return -1;
    pthread_mutex_lock(&h->_lock);

    if (h->_locked) {
        pthread_mutex_unlock(&h->_lock);
        return 0;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    uint8_t *inner_base = (uint8_t *)h->_outer + (size_t)page_size;
    size_t   inner_size = page_align_up(CANARY_FLAT_OVERHEAD + h->data_len);

    /* Verify canaries BEFORE locking — corrupted keys must never be reused */
    if (canary_flat_check(inner_base, h->data_len) != 0) {
        fprintf(stderr, "FATAL: vault canary corruption in '%s' — aborting\n",
                h->label);
        abort();
    }

    if (mprotect(inner_base, inner_size, PROT_NONE) != 0) {
        pthread_mutex_unlock(&h->_lock);
        return -1;
    }

    h->_locked = 1;
    pthread_mutex_unlock(&h->_lock);
    return 0;
}

/* ── vault_free ───────────────────────────────────────────────────────────── */

void vault_free(VaultHandle **h_ptr)
{
    if (!h_ptr || !*h_ptr) return;
    VaultHandle *h = *h_ptr;

    /* Unlock so we can scrub */
    if (h->_locked) vault_unlock(h);

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    uint8_t *inner_base = (uint8_t *)h->_outer + (size_t)page_size;
    size_t   inner_size = page_align_up(CANARY_FLAT_OVERHEAD + h->data_len);

    /*
     * OPENSSL_cleanse() — the ONLY safe way to zero secret material.
     * Unlike memset(), it uses a volatile write loop + memory barrier.
     */
    OPENSSL_cleanse(inner_base, inner_size);

    /* munmap — OS reclaims pages; no free-list leakage */
    (void)munmap(h->_outer, h->_outer_len);

    registry_remove(h);
    pthread_mutex_destroy(&h->_lock);

    OPENSSL_cleanse(h, sizeof(VaultHandle));
    free(h);
    *h_ptr = NULL;
}

/* ── vault_lock_memory (simple API) ───────────────────────────────────────── */

int vault_lock_memory(void *addr, size_t len)
{
    if (!addr || len == 0) return -1;
    return mlock(addr, len);
}

/* ── vault_zeroize (simple API) ───────────────────────────────────────────── */

void vault_zeroize(void *buf, size_t len)
{
    if (!buf || len == 0) return;
    OPENSSL_cleanse(buf, len);
    /* Memory barrier — prevent reordering past this point */
    __asm__ __volatile__("" ::: "memory");
}

/* ── vault_destroy ────────────────────────────────────────────────────────── */

void vault_destroy(void)
{
    /* Free all remaining vaults (iterate in reverse) */
    while (1) {
        pthread_mutex_lock(&g_registry.lock);
        if (g_registry.count == 0) {
            pthread_mutex_unlock(&g_registry.lock);
            break;
        }
        VaultHandle *h = g_registry.entries[g_registry.count - 1];
        pthread_mutex_unlock(&g_registry.lock);
        vault_free(&h);
    }

    munlockall();
}
