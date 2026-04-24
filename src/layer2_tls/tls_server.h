/*
 * tls_server.h — PQC TLS 1.3 Server (Layer 2 — Transport)
 *
 * Standalone TLS 1.3 server enforcing X25519MLKEM768 as the ONLY
 * accepted key exchange group. Uses OpenSSL 3.2.1 + oqs-provider.
 *
 * Security decisions:
 *   - X25519MLKEM768 ONLY — no fallback groups
 *   - PSK disabled        — no session reuse attack surface
 *   - 0-RTT disabled      — inherently replay-vulnerable
 *   - Session tickets OFF  — no ticket oracle attacks
 *
 * Authors: Ojas Sharma & Anant Tripathi — SRM University
 */

#ifndef PQC_TLS_SERVER_H
#define PQC_TLS_SERVER_H

#include <stdint.h>

/*
 * tls_server_init() — create SSL_CTX, load certs, bind socket.
 *   port      — listening port (default 8443)
 *   cert_path — PEM certificate (may use ML-DSA-65 or P-256)
 *   key_path  — PEM private key
 *
 * Returns: 0 on success, -1 on failure.
 */
int tls_server_init(uint16_t port,
                    const char *cert_path,
                    const char *key_path);

/*
 * tls_server_init_from_fd() — same as above but with pre-bound socket fd.
 * Used when main.c binds sockets as root before dropping privileges.
 */
int tls_server_init_from_fd(int listen_fd,
                            const char *cert_path,
                            const char *key_path);

/*
 * tls_server_run() — blocking accept loop. Call from a dedicated pthread.
 * Returns NULL (pthread signature). Handles SIGINT/SIGTERM via g_shutdown.
 */
void *tls_server_run(void *arg);

/*
 * tls_server_shutdown() — clean up SSL_CTX, close socket.
 */
void tls_server_shutdown(void);

#endif /* PQC_TLS_SERVER_H */
