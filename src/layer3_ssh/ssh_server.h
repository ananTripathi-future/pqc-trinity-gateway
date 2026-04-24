/*
 * ssh_server.h — PQC SSH Server (Layer 3 — Management)
 *
 * Custom SSH server on port 2222 using libssh for the SSHv2 protocol
 * engine, with ML-DSA-65 host key authentication injected via a wrapper.
 *
 * Port 22: classical SSH (legacy, for migration path)
 * Port 2222: quantum-hardened SSH with ML-DSA-65 host keys
 *
 * Authors: Ojas Sharma & Anant Tripathi — SRM University
 */

#ifndef PQC_SSH_SERVER_H
#define PQC_SSH_SERVER_H

#include <stdint.h>

/*
 * ssh_server_init() — bind to port, load ML-DSA-65 host key.
 *   port         — listening port (default 2222)
 *   hostkey_path — path to Ed25519 host key (wire compatibility)
 *   mldsa_sk     — path to ML-DSA-65 private key (PQC extension)
 *   mldsa_pk     — path to ML-DSA-65 public key
 *
 * Returns: 0 on success, -1 on failure.
 */
int ssh_server_init(uint16_t port,
                    const char *hostkey_path,
                    const char *mldsa_sk_path,
                    const char *mldsa_pk_path);

/*
 * ssh_server_init_from_fd() — same but with pre-bound socket.
 */
int ssh_server_init_from_fd(int listen_fd,
                            const char *hostkey_path,
                            const char *mldsa_sk_path,
                            const char *mldsa_pk_path);

/*
 * ssh_server_run() — blocking accept loop. Call from a dedicated pthread.
 */
void *ssh_server_run(void *arg);

/*
 * ssh_server_shutdown() — clean up libssh resources, zeroize keys.
 */
void ssh_server_shutdown(void);

#endif /* PQC_SSH_SERVER_H */
