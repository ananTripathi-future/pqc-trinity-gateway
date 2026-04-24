/*
 * ipsec_manager.h — PQC IPsec Manager (Layer 1 — Network)
 *
 * Manages a strongSwan instance as a subprocess. Generates IKEv2
 * configuration with ML-KEM-768 hybrid key exchange, and monitors
 * state via the VICI (Versatile IKE Control Interface) socket.
 *
 * Does NOT implement IKEv2 from scratch — delegates to strongSwan charon.
 *
 * Authors: Ojas Sharma & Anant Tripathi — SRM University
 */

#ifndef PQC_IPSEC_MANAGER_H
#define PQC_IPSEC_MANAGER_H

#include <stdint.h>

/*
 * ipsec_manager_init() — generate strongSwan config, connect to VICI.
 * Returns: 0 on success, -1 on failure.
 */
int ipsec_manager_init(void);

/*
 * ipsec_manager_run() — blocking VICI event loop. Call from a pthread.
 * Monitors IKE-UP, CHILD-UP, IKE-DOWN events and writes to audit log.
 */
void *ipsec_manager_run(void *arg);

/*
 * ipsec_manager_shutdown() — disconnect VICI, clean up.
 */
void ipsec_manager_shutdown(void);

#endif /* PQC_IPSEC_MANAGER_H */
