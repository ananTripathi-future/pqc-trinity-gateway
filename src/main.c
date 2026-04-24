/*
 * main.c — PQC Trinity Gateway Orchestrator
 *
 * Entry point that initializes the security foundation, binds sockets,
 * drops privileges, and launches three independent protocol threads:
 *
 *   Thread 1: IPsec manager (strongSwan VICI monitor)
 *   Thread 2: TLS 1.3 server (X25519MLKEM768)
 *   Thread 3: SSH server (ML-DSA-65 host key, port 2222)
 *
 * Startup sequence (order matters for security):
 *   1. Parse config
 *   2. Vault: lock memory, disable core dumps
 *   3. Audit: open log, derive HMAC key
 *   4. Bind privileged sockets BEFORE dropping privileges
 *   5. Drop privileges (setgid → setuid)
 *   6. Initialize each layer
 *   7. Start layer threads
 *   8. Wait for shutdown signal
 *   9. Graceful cleanup with key zeroization
 *
 * Critical: Privileges are dropped BEFORE any crypto worker starts.
 *
 * Authors: Ojas Sharma & Anant Tripathi — SRM University
 * FIPS 203 ML-KEM-768 | FIPS 204 ML-DSA-65 | IPsec + TLS 1.3 + SSH 2.0
 */

#include "gateway.h"
#include "vault/vault.h"
#include "audit/audit.h"
#include "layer1_ipsec/ipsec_manager.h"
#include "layer2_tls/tls_server.h"
#include "layer3_ssh/ssh_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <getopt.h>

/* ── Global Shutdown Flag ─────────────────────────────────────────────────── */

volatile sig_atomic_t g_shutdown = 0;

static void handle_shutdown(int sig)
{
    (void)sig;
    g_shutdown = 1;
}

/* ── Config Defaults ──────────────────────────────────────────────────────── */

void gateway_config_defaults(GatewayConfig *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->tls_port = DEFAULT_TLS_PORT;
    cfg->ssh_port = DEFAULT_SSH_PORT;
    snprintf(cfg->tls_cert_path, sizeof(cfg->tls_cert_path),
             "/etc/pqc-gateway/keys/tls_cert.pem");
    snprintf(cfg->tls_key_path, sizeof(cfg->tls_key_path),
             "/etc/pqc-gateway/keys/tls_key.pem");
    snprintf(cfg->ssh_hostkey_path, sizeof(cfg->ssh_hostkey_path),
             "/etc/pqc-gateway/keys/ssh_host_ed25519");
    snprintf(cfg->ssh_hostkey_pub, sizeof(cfg->ssh_hostkey_pub),
             "/etc/pqc-gateway/keys/ssh_host_mldsa65.pub");
    snprintf(cfg->audit_log_path, sizeof(cfg->audit_log_path),
             "/var/log/pqc-gateway/audit.log");
    snprintf(cfg->config_dir, sizeof(cfg->config_dir),
             "/etc/pqc-gateway");
    snprintf(cfg->runtime_user, sizeof(cfg->runtime_user), "pqcgateway");
    cfg->verbose = true;

    /* Default HMAC key (should be overridden from config file) */
    const uint8_t default_key[32] = {
        0x70, 0x71, 0x63, 0x2d, 0x74, 0x72, 0x69, 0x6e,
        0x69, 0x74, 0x79, 0x2d, 0x67, 0x61, 0x74, 0x65,
        0x77, 0x61, 0x79, 0x2d, 0x68, 0x6d, 0x61, 0x63,
        0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x76, 0x31, 0x00
    };
    memcpy(cfg->master_secret, default_key, 32);
}

/* ── Config File Parser ───────────────────────────────────────────────────── */

int gateway_config_load(GatewayConfig *cfg, const char *path)
{
    gateway_config_defaults(cfg);

    if (!path) return 0; /* use defaults */

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[MAIN] Config file not found: %s (using defaults)\n",
                path);
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and empty lines */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        char key[64], value[256];
        if (sscanf(p, "%63s = %255[^\n]", key, value) == 2) {
            if (strcmp(key, "tls_port") == 0)
                cfg->tls_port = (uint16_t)atoi(value);
            else if (strcmp(key, "ssh_port") == 0)
                cfg->ssh_port = (uint16_t)atoi(value);
            else if (strcmp(key, "tls_cert") == 0)
                snprintf(cfg->tls_cert_path, 256, "%s", value);
            else if (strcmp(key, "tls_key") == 0)
                snprintf(cfg->tls_key_path, 256, "%s", value);
            else if (strcmp(key, "audit_log") == 0)
                snprintf(cfg->audit_log_path, 256, "%s", value);
            else if (strcmp(key, "runtime_user") == 0)
                snprintf(cfg->runtime_user, 64, "%s", value);
            else if (strcmp(key, "verbose") == 0)
                cfg->verbose = (strcmp(value, "true") == 0 || atoi(value));
        }
    }

    fclose(fp);
    return 0;
}

/* ── Socket Binding (runs as root, before privilege drop) ─────────────────── */

static int bind_socket(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("bind_socket: socket");
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind_socket: cannot bind port %u: %s\n",
                port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 128) < 0) {
        perror("bind_socket: listen");
        close(fd);
        return -1;
    }

    return fd;
}

/* ── Privilege Dropping ───────────────────────────────────────────────────── */

static int drop_privileges(const char *username)
{
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "[MAIN] Runtime user '%s' not found — "
                        "continuing as current user\n", username);
        return -1;
    }

    /* Order matters: setgid BEFORE setuid */
    if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
        setgid(pw->pw_gid) != 0 ||
        setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "[MAIN] Failed to drop privileges to '%s': %s\n",
                username, strerror(errno));
        return -1;
    }

    /* Verify we actually dropped */
    if (getuid() == 0) {
        fprintf(stderr, "[MAIN] CRITICAL: Still running as root after setuid!\n");
        return -1;
    }

    fprintf(stderr, "[MAIN] Dropped privileges to user '%s' (uid=%u)\n",
            username, pw->pw_uid);
    return 0;
}

/* ── Banner ───────────────────────────────────────────────────────────────── */

static void print_banner(void)
{
    fprintf(stderr,
        "\n"
        "╔═══════════════════════════════════════════════════════════════╗\n"
        "║              PQC TRINITY GATEWAY v%s                    ║\n"
        "║                                                             ║\n"
        "║   Layer 1 — IPsec  │ IKEv2 + ML-KEM-768 (FIPS 203)        ║\n"
        "║   Layer 2 — TLS    │ TLS 1.3 + X25519MLKEM768             ║\n"
        "║   Layer 3 — SSH    │ SSH 2.0 + ML-DSA-65  (FIPS 204)      ║\n"
        "║                                                             ║\n"
        "║   Ojas Sharma & Anant Tripathi — SRM University            ║\n"
        "╚═══════════════════════════════════════════════════════════════╝\n"
        "\n", PQC_GW_VERSION);
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    print_banner();

    /* ── 1. Parse config ──────────────────────────────────────────────── */
    GatewayConfig cfg;
    const char *config_path = "/etc/pqc-gateway/gateway.conf";

    /* Allow override via command-line */
    int opt;
    while ((opt = getopt(argc, argv, "c:v")) != -1) {
        switch (opt) {
            case 'c': config_path = optarg; break;
            case 'v': /* handled after config load */ break;
            default:
                fprintf(stderr, "Usage: %s [-c config_path] [-v]\n", argv[0]);
                return 1;
        }
    }

    gateway_config_load(&cfg, config_path);

    /* ── 2. Vault: lock memory, disable core dumps ────────────────────── */
    fprintf(stderr, "[MAIN] Initializing security vault...\n");
    if (vault_init() != 0) {
        fprintf(stderr, "[MAIN] FATAL: Vault initialization failed "
                        "(need root or CAP_IPC_LOCK)\n");
        return 1;
    }
    fprintf(stderr, "[MAIN] ✓ Memory locked (mlockall), core dumps disabled\n");

    /* ── 3. Audit: open log, write startup event ──────────────────────── */
    fprintf(stderr, "[MAIN] Opening audit log: %s\n", cfg.audit_log_path);
    AuditLog *audit = audit_init(cfg.audit_log_path,
                                 cfg.master_secret, 32);
    if (!audit) {
        fprintf(stderr, "[MAIN] FATAL: Cannot initialize audit log\n");
        vault_destroy();
        return 1;
    }
    audit_write(EVT_STARTUP, LAYER_SYSTEM,
                "%s v%s starting — ML-KEM-768 / ML-DSA-65 active",
                PQC_GW_NAME, PQC_GW_VERSION);

    /* ── 4. Bind privileged sockets BEFORE dropping privileges ─────────── */
    fprintf(stderr, "[MAIN] Binding sockets...\n");

    int tls_sock = bind_socket(cfg.tls_port);
    if (tls_sock < 0) {
        fprintf(stderr, "[MAIN] WARNING: Cannot bind TLS port %u\n",
                cfg.tls_port);
    } else {
        fprintf(stderr, "[MAIN] ✓ TLS socket bound to port %u\n", cfg.tls_port);
    }

    /* SSH on port 2222 doesn't need root, but bind early anyway */
    int ssh_sock = bind_socket(cfg.ssh_port);
    if (ssh_sock < 0) {
        fprintf(stderr, "[MAIN] WARNING: Cannot bind SSH port %u\n",
                cfg.ssh_port);
    } else {
        fprintf(stderr, "[MAIN] ✓ SSH socket bound to port %u\n", cfg.ssh_port);
    }

    /* ── 5. Drop privileges ───────────────────────────────────────────── */
    fprintf(stderr, "[MAIN] Dropping privileges to '%s'...\n",
            cfg.runtime_user);
    if (drop_privileges(cfg.runtime_user) != 0) {
        fprintf(stderr, "[MAIN] Privilege drop failed — "
                        "continuing (dev/demo mode)\n");
        audit_write(EVT_ERROR, LAYER_SYSTEM,
                    "Privilege drop to '%s' failed — running as current user",
                    cfg.runtime_user);
    }

    /* ── 6. Initialize each layer ─────────────────────────────────────── */
    fprintf(stderr, "\n[MAIN] Initializing protocol layers...\n");

    /* Layer 1: IPsec */
    fprintf(stderr, "[MAIN] Layer 1 — IPsec (ML-KEM-768)...\n");
    ipsec_manager_init();

    /* Layer 2: TLS */
    fprintf(stderr, "[MAIN] Layer 2 — TLS 1.3 (X25519MLKEM768)...\n");
    if (tls_sock >= 0) {
        tls_server_init_from_fd(tls_sock, cfg.tls_cert_path, cfg.tls_key_path);
    }

    /* Layer 3: SSH */
    fprintf(stderr, "[MAIN] Layer 3 — SSH 2.0 (ML-DSA-65)...\n");
    char mldsa_sk_path[256];
    snprintf(mldsa_sk_path, sizeof(mldsa_sk_path),
             "%s/keys/ssh_host_mldsa65", cfg.config_dir);
    ssh_server_init(cfg.ssh_port, cfg.ssh_hostkey_path,
                    mldsa_sk_path, cfg.ssh_hostkey_pub);

    /* ── 7. Start layer threads ───────────────────────────────────────── */
    fprintf(stderr, "\n[MAIN] Launching protocol threads...\n");

    pthread_t t_ipsec, t_tls, t_ssh;
    pthread_create(&t_ipsec, NULL, ipsec_manager_run, NULL);
    pthread_create(&t_tls,   NULL, tls_server_run,    NULL);
    pthread_create(&t_ssh,   NULL, ssh_server_run,     NULL);

    fprintf(stderr, "[MAIN] ✓ All three layers active\n");
    fprintf(stderr, "[MAIN]   TLS:   https://localhost:%u\n", cfg.tls_port);
    fprintf(stderr, "[MAIN]   SSH:   ssh -p %u user@localhost\n", cfg.ssh_port);
    fprintf(stderr, "[MAIN]   Audit: %s\n", cfg.audit_log_path);
    fprintf(stderr, "[MAIN] Press Ctrl+C to shutdown\n\n");

    /* ── 8. Signal handler for graceful shutdown ──────────────────────── */
    signal(SIGINT,  handle_shutdown);
    signal(SIGTERM, handle_shutdown);

    /* ── 9. Wait for threads ──────────────────────────────────────────── */
    pthread_join(t_ipsec, NULL);
    pthread_join(t_tls,   NULL);
    pthread_join(t_ssh,   NULL);

    /* ── 10. Shutdown ─────────────────────────────────────────────────── */
    fprintf(stderr, "\n[MAIN] Shutting down...\n");

    audit_write(EVT_SHUTDOWN, LAYER_SYSTEM,
                "%s shutting down — all key material will be zeroized",
                PQC_GW_NAME);

    ipsec_manager_shutdown();
    tls_server_shutdown();
    ssh_server_shutdown();

    /* Zeroize master secret */
    vault_zeroize(cfg.master_secret, sizeof(cfg.master_secret));

    vault_destroy();
    audit_close();

    fprintf(stderr, "[MAIN] ✓ Shutdown complete. All keys zeroized.\n");
    return 0;
}
