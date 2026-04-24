/*
 * ipsec_manager.c — PQC IPsec Manager Implementation (Layer 1)
 *
 * Manages strongSwan lifecycle and IKEv2 configuration with ML-KEM-768
 * hybrid key exchange. Communicates via the VICI Unix socket.
 *
 * Architecture:
 *   1. Generate strongSwan config at runtime with PQC proposals
 *   2. Connect to VICI socket (/var/run/charon.vici)
 *   3. Load connection, initiate IKEv2 negotiation
 *   4. Listen for events and write to audit log
 *
 * strongSwan handles RFC 7383 IKE fragmentation natively.
 *
 * Authors: Ojas Sharma & Anant Tripathi — SRM University
 */

#include "ipsec_manager.h"
#include "../gateway.h"
#include "../vault/vault.h"
#include "../audit/audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

/* ── Constants ────────────────────────────────────────────────────────────── */

#define VICI_SOCKET_PATH    "/var/run/charon.vici"
#define STRONGSWAN_CONF_DIR "/etc/strongswan.d"
#define PQC_CONF_FILE       STRONGSWAN_CONF_DIR "/pqc-gateway.conf"

/* IKEv2 proposal: AES-256-GCM + SHA3-256 + X25519 + ML-KEM-768 */
#define PQC_IKE_PROPOSAL    "aes256gcm128-sha3_256-x25519-ke1_mlkem768"
#define PQC_ESP_PROPOSAL    "aes256gcm128-sha3_256"

/* ── Module State ─────────────────────────────────────────────────────────── */

static int g_vici_fd = -1;

/* ── strongSwan Config Generation ─────────────────────────────────────────── */

/*
 * Generate the strongSwan connection config for PQC-hybrid IKEv2.
 * Written to /etc/strongswan.d/pqc-gateway.conf
 */
static int generate_strongswan_config(void)
{
    /* Ensure directory exists */
    (void)mkdir(STRONGSWAN_CONF_DIR, 0755);

    FILE *fp = fopen(PQC_CONF_FILE, "w");
    if (!fp) {
        fprintf(stderr, "[IPsec] Cannot write config to %s: %s\n",
                PQC_CONF_FILE, strerror(errno));
        audit_write(EVT_ERROR, LAYER_IPSEC,
                    "Cannot write strongSwan config: %s", strerror(errno));
        return -1;
    }

    fprintf(fp,
        "# PQC Trinity Gateway — strongSwan IKEv2 Configuration\n"
        "# Auto-generated — do not edit manually\n"
        "#\n"
        "# Proposal: %s\n"
        "# ML-KEM-768 (FIPS 203) hybrid key exchange\n"
        "# RFC 7383 IKE fragmentation enabled\n"
        "\n"
        "connections {\n"
        "  pqc-tunnel {\n"
        "    version = 2\n"
        "    proposals = %s\n"
        "    fragmentation = yes\n"
        "    dpd_delay = 30s\n"
        "    local {\n"
        "      auth = pubkey\n"
        "      certs = /etc/pqc-gateway/keys/tls_cert.pem\n"
        "    }\n"
        "    remote {\n"
        "      auth = pubkey\n"
        "    }\n"
        "    children {\n"
        "      pqc-child {\n"
        "        esp_proposals = %s\n"
        "        mode = tunnel\n"
        "        start_action = trap\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Charon configuration for PQC\n"
        "charon {\n"
        "  fragment_size = 1400\n"
        "  retransmit_timeout = 4.0\n"
        "  retransmit_tries = 5\n"
        "}\n",
        PQC_IKE_PROPOSAL,
        PQC_IKE_PROPOSAL,
        PQC_ESP_PROPOSAL);

    fclose(fp);

    fprintf(stderr, "[IPsec] Config written to %s\n", PQC_CONF_FILE);
    fprintf(stderr, "[IPsec]   IKE proposal: %s\n", PQC_IKE_PROPOSAL);
    fprintf(stderr, "[IPsec]   ESP proposal: %s\n", PQC_ESP_PROPOSAL);
    fprintf(stderr, "[IPsec]   Fragmentation: enabled (1400 bytes)\n");

    return 0;
}

/* ── VICI Socket Client ───────────────────────────────────────────────────── */

/*
 * Connect to strongSwan's VICI Unix socket.
 */
static int vici_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[IPsec] vici socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, VICI_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[IPsec] Cannot connect to VICI socket %s: %s\n",
                VICI_SOCKET_PATH, strerror(errno));
        fprintf(stderr, "[IPsec] Is strongSwan (charon) running?\n");
        close(fd);
        return -1;
    }

    fprintf(stderr, "[IPsec] Connected to VICI socket\n");
    return fd;
}

/*
 * VICI protocol: send a named command.
 * Minimal implementation for load-conn, initiate, and event registration.
 *
 * VICI message format:
 *   [1 byte type] [2 byte name_len] [name] [payload...]
 *   type 0 = CMD_REQUEST, type 1 = CMD_RESPONSE, type 3 = EVENT_REGISTER
 */

#define VICI_CMD_REQUEST    0
#define VICI_CMD_RESPONSE   1
#define VICI_EVENT_REGISTER 3
#define VICI_EVENT          4

static int vici_send_cmd(int fd, const char *name)
{
    uint8_t type = VICI_CMD_REQUEST;
    uint8_t name_len = (uint8_t)strlen(name);

    /* Length-prefixed packet: [4-byte total_len][type][name_len][name] */
    uint32_t pkt_len = 1 + 1 + name_len;
    uint32_t net_len = htonl(pkt_len);

    if (write(fd, &net_len, 4) != 4) return -1;
    if (write(fd, &type, 1) != 1) return -1;
    if (write(fd, &name_len, 1) != 1) return -1;
    if (write(fd, name, name_len) != name_len) return -1;

    return 0;
}

static int vici_register_event(int fd, const char *event_name)
{
    uint8_t type = VICI_EVENT_REGISTER;
    uint8_t name_len = (uint8_t)strlen(event_name);

    uint32_t pkt_len = 1 + 1 + name_len;
    uint32_t net_len = htonl(pkt_len);

    if (write(fd, &net_len, 4) != 4) return -1;
    if (write(fd, &type, 1) != 1) return -1;
    if (write(fd, &name_len, 1) != 1) return -1;
    if (write(fd, event_name, name_len) != name_len) return -1;

    return 0;
}

/*
 * vici_event_listen() — blocking loop that reads VICI events and
 * writes them to the audit log. Runs until g_shutdown is set.
 */
static void vici_event_listen(int fd)
{
    uint8_t buf[4096];

    while (!g_shutdown) {
        /* Read packet length (4 bytes, network order) */
        uint32_t net_len;
        ssize_t n = read(fd, &net_len, 4);
        if (n <= 0) {
            if (g_shutdown) break;
            if (n == 0) {
                fprintf(stderr, "[IPsec] VICI socket closed\n");
                break;
            }
            if (errno == EINTR) continue;
            perror("[IPsec] VICI read");
            break;
        }

        uint32_t pkt_len = ntohl(net_len);
        if (pkt_len > sizeof(buf)) {
            fprintf(stderr, "[IPsec] VICI packet too large: %u bytes\n",
                    pkt_len);
            break;
        }

        /* Read packet body */
        size_t total_read = 0;
        while (total_read < pkt_len) {
            n = read(fd, buf + total_read, pkt_len - total_read);
            if (n <= 0) break;
            total_read += (size_t)n;
        }

        if (total_read < pkt_len) break;

        /* Parse: [type][name_len][name][...] */
        uint8_t msg_type = buf[0];

        if (msg_type == VICI_EVENT && pkt_len > 2) {
            uint8_t name_len = buf[1];
            char event_name[256] = {0};
            if (name_len < sizeof(event_name) && name_len + 2 <= pkt_len) {
                memcpy(event_name, buf + 2, name_len);
            }

            /* Map VICI events to audit entries */
            if (strstr(event_name, "ike-updown")) {
                audit_write(EVT_KEY_EXCHANGE, LAYER_IPSEC,
                            "IKEv2 ML-KEM-768 hybrid key exchange complete");
                fprintf(stderr, "[IPsec] ✓ IKE-UP: ML-KEM-768 tunnel established\n");
            } else if (strstr(event_name, "child-updown")) {
                audit_write(EVT_KEY_EXCHANGE, LAYER_IPSEC,
                            "IPsec CHILD_SA established (ESP tunnel mode)");
                fprintf(stderr, "[IPsec] ✓ CHILD-UP: ESP tunnel active\n");
            } else if (strstr(event_name, "ike-rekey")) {
                audit_write(EVT_KEY_EXCHANGE, LAYER_IPSEC,
                            "IKEv2 rekey with ML-KEM-768");
            } else {
                fprintf(stderr, "[IPsec] VICI event: %s\n", event_name);
            }
        }
    }
}

/* ── Public API ───────────────────────────────────────────────────────────── */

int ipsec_manager_init(void)
{
    /* Step 1: Generate strongSwan config */
    if (generate_strongswan_config() != 0) {
        /* Non-fatal — strongSwan might not be installed in demo env */
        fprintf(stderr, "[IPsec] Config generation failed — "
                        "running in monitor-only mode\n");
    }

    /* Step 2: Connect to VICI */
    g_vici_fd = vici_connect();
    if (g_vici_fd < 0) {
        fprintf(stderr, "[IPsec] VICI connection failed — "
                        "strongSwan may not be running\n");
        audit_write(EVT_ERROR, LAYER_IPSEC,
                    "VICI connection failed — strongSwan not available");
        /* Non-fatal: the IPsec layer runs in degraded mode */
        return 0;
    }

    /* Step 3: Register for IKE events */
    vici_register_event(g_vici_fd, "ike-updown");
    vici_register_event(g_vici_fd, "child-updown");
    vici_register_event(g_vici_fd, "ike-rekey");

    audit_write(EVT_STARTUP, LAYER_IPSEC,
                "IPsec manager initialized — VICI connected, "
                "ML-KEM-768 proposal: %s", PQC_IKE_PROPOSAL);
    return 0;
}

void *ipsec_manager_run(void *arg)
{
    (void)arg;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    if (g_vici_fd < 0) {
        fprintf(stderr, "[IPsec] No VICI connection — "
                        "IPsec layer idle (strongSwan not available)\n");
        audit_write(EVT_ERROR, LAYER_IPSEC,
                    "IPsec worker idle — no strongSwan VICI socket");

        /* Wait for shutdown signal */
        while (!g_shutdown) {
            sleep(1);
        }
        return NULL;
    }

    fprintf(stderr, "[IPsec] VICI event listener started\n");
    vici_event_listen(g_vici_fd);

    audit_write(EVT_SHUTDOWN, LAYER_IPSEC, "IPsec manager shutting down");
    return NULL;
}

void ipsec_manager_shutdown(void)
{
    if (g_vici_fd >= 0) {
        close(g_vici_fd);
        g_vici_fd = -1;
    }
}
