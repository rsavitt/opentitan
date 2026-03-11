// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_AGENT_TRUST_AGENT_TRUST_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_AGENT_TRUST_AGENT_TRUST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/hardened.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/device/silicon_creator/lib/drivers/keymgr.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/keymgr_binding_value.h"
#include "sw/device/silicon_creator/lib/sigverify/ecdsa_p256_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief Hardware Root of Trust for AI Agents.
 *
 * This library provides hardware-backed trust primitives for AI agent
 * infrastructure using OpenTitan's Earl Grey security features. It implements
 * five patterns:
 *
 *   Pattern 1: Hardware identity for agent hosts
 *   Pattern 2: Seal agent secrets to approved software state
 *   Pattern 3: Signed provenance for agent actions
 *   Pattern 4: Policy-gated task execution (attestation admission control)
 *   Pattern 5: Tamper response and quarantine
 *
 * All patterns build on OpenTitan's key manager (DICE), lifecycle controller,
 * alert handler, and OTBN crypto accelerator.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

enum {
  /**
   * Maximum size of an agent workload identity string in bytes.
   */
  kAgentTrustWorkloadIdMaxBytes = 64,
  /**
   * Size of agent trust salt in 32-bit words (matches keymgr salt).
   */
  kAgentTrustSaltNumWords = 8,
  /**
   * Size of the provenance signature payload tag in bytes.
   */
  kAgentTrustProvenanceTagBytes = 4,
  /**
   * Maximum number of alert classes monitored for tamper response.
   */
  kAgentTrustMaxAlertClasses = 4,
  /**
   * Size of a policy version identifier in 32-bit words.
   */
  kAgentTrustPolicyVersionWords = 4,
  /**
   * Maximum size of a task token in bytes.
   */
  kAgentTrustTaskTokenMaxBytes = 64,
};

// ---------------------------------------------------------------------------
// Pattern 1: Hardware Identity for Agent Hosts
// ---------------------------------------------------------------------------

/**
 * Agent host identity derived from the DICE attestation chain.
 *
 * Binds the device identifier, boot measurements, lifecycle state, and
 * owner chain into a single attestation bundle that an orchestration layer
 * can verify before admitting an agent host to the swarm.
 */
typedef struct agent_trust_identity {
  /** Device identifier from OTP HW_CFG0 partition. */
  lifecycle_device_id_t device_id;
  /** Current lifecycle state of the device. */
  lifecycle_state_t lc_state;
  /** Hardware revision information. */
  lifecycle_hw_rev_t hw_rev;
  /** ECC P256 public key from the current DICE attestation stage. */
  ecdsa_p256_public_key_t pubkey;
  /** SHA-256 key ID of the attestation public key. */
  hmac_digest_t pubkey_id;
  /** Boot measurement of ROM_EXT used in key derivation. */
  keymgr_binding_value_t rom_ext_measurement;
  /** Boot measurement of BL0 / owner firmware. */
  keymgr_binding_value_t bl0_measurement;
} agent_trust_identity_t;

/**
 * Collects the hardware identity for this agent host.
 *
 * Reads the device identifier, lifecycle state, hardware revision, and
 * generates the current DICE attestation keypair via the key manager and
 * OTBN. The key manager must have been advanced to at least the
 * OwnerIntermediateKey (CDI_0) stage before calling this function.
 *
 * @param key Descriptor for the ECC key to generate (e.g. kDiceKeyCdi0).
 * @param[out] identity Populated agent host identity structure.
 * @return kErrorOk on success.
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_identity_collect(const sc_keymgr_ecc_key_t *key,
                                         agent_trust_identity_t *identity);

/**
 * Computes a SHA-256 digest over the agent host identity.
 *
 * This digest can be used as a compact identifier for admission control
 * decisions or included in attestation certificates.
 *
 * @param identity The agent host identity to hash.
 * @param[out] digest The resulting SHA-256 digest.
 * @return kErrorOk on success.
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_identity_digest(const agent_trust_identity_t *identity,
                                        hmac_digest_t *digest);

// ---------------------------------------------------------------------------
// Pattern 2: Seal Agent Secrets to Approved Software State
// ---------------------------------------------------------------------------

/**
 * Sealing policy that defines the conditions under which a secret can be
 * unwrapped.
 */
typedef struct agent_trust_seal_policy {
  /** Required lifecycle state (e.g. kLcStateProd). */
  lifecycle_state_t required_lc_state;
  /** Attestation binding value expected from the boot chain. */
  keymgr_binding_value_t required_attestation_binding;
  /** Sealing binding value expected from the boot chain. */
  keymgr_binding_value_t required_sealing_binding;
  /** Anti-rollback: minimum firmware security version. */
  uint32_t min_security_version;
} agent_trust_seal_policy_t;

/**
 * Derives a sealing key bound to the current measured boot state.
 *
 * The derived key can only be reproduced on the same device, with the same
 * owner chain, and (if attestation-type) the same firmware version. This
 * implements the "agent credential only exists on approved measured hosts"
 * guarantee.
 *
 * Precondition: the key manager must be in the correct state for the
 * requested key type.
 *
 * @param diversification Salt and version for key derivation.
 * @param key_type kScKeymgrKeyTypeSealing for ownership-stable keys,
 *                 kScKeymgrKeyTypeAttestation for firmware-bound keys.
 * @param dest Hardware block to sideload the derived key into.
 * @return kErrorOk on success.
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_seal_key_derive(
    sc_keymgr_diversification_t diversification,
    sc_keymgr_key_type_t key_type, sc_keymgr_dest_t dest);

/**
 * Validates the current device state against a sealing policy.
 *
 * Checks lifecycle state, binding values, and security version. Returns
 * kHardenedBoolTrue only if all policy conditions are met.
 *
 * @param policy The sealing policy to check against.
 * @param[out] result kHardenedBoolTrue if the policy is satisfied.
 * @return kErrorOk on success.
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_seal_policy_check(
    const agent_trust_seal_policy_t *policy, hardened_bool_t *result);

// ---------------------------------------------------------------------------
// Pattern 3: Signed Provenance for Agent Actions
// ---------------------------------------------------------------------------

/**
 * Provenance metadata attached to agent-produced artifacts.
 *
 * Every high-impact action can be signed by a key derived from the device
 * identity, workload identity, boot measurement, and policy version.
 */
typedef struct agent_trust_provenance {
  /** Tag identifying the provenance record format version. */
  uint8_t tag[kAgentTrustProvenanceTagBytes];
  /** Device identifier of the agent host. */
  lifecycle_device_id_t device_id;
  /** Lifecycle state at time of signing. */
  lifecycle_state_t lc_state;
  /** SHA-256 digest of the workload identity string. */
  hmac_digest_t workload_id_digest;
  /** Boot measurement incorporated into the signing key. */
  keymgr_binding_value_t boot_measurement;
  /** Policy version identifier. */
  uint32_t policy_version[kAgentTrustPolicyVersionWords];
} agent_trust_provenance_t;

/**
 * Builds a provenance record for the current agent state.
 *
 * Populates the provenance structure with the device identity, lifecycle
 * state, workload identity digest, boot measurement, and policy version.
 *
 * @param workload_id Workload identity string (e.g. container image hash).
 * @param workload_id_len Length of the workload identity string.
 * @param policy_version Policy version words.
 * @param boot_measurement Boot measurement from the current stage.
 * @param[out] provenance The populated provenance record.
 * @return kErrorOk on success.
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_provenance_build(
    const uint8_t *workload_id, size_t workload_id_len,
    const uint32_t policy_version[kAgentTrustPolicyVersionWords],
    const keymgr_binding_value_t *boot_measurement,
    agent_trust_provenance_t *provenance);

/**
 * Signs a message digest together with provenance metadata.
 *
 * The provenance record is hashed together with the caller-supplied digest
 * to produce a composite digest, which is then signed using the attestation
 * private key previously saved to OTBN's scratchpad.
 *
 * Precondition: `otbn_boot_attestation_key_save()` must have been called.
 *
 * @param provenance The provenance record to bind into the signature.
 * @param message_digest SHA-256 digest of the artifact being signed.
 * @param[out] sig The resulting ECDSA-P256 signature.
 * @return kErrorOk on success.
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_provenance_sign(
    const agent_trust_provenance_t *provenance,
    const hmac_digest_t *message_digest, ecdsa_p256_signature_t *sig);

// ---------------------------------------------------------------------------
// Pattern 4: Policy-Gated Task Execution (Attestation Admission Control)
// ---------------------------------------------------------------------------

/**
 * Task admission policy checked before issuing a task token.
 *
 * The control plane verifies attestation state before allowing the agent
 * to receive a sensitive task.
 */
typedef struct agent_trust_admission_policy {
  /** Set of lifecycle states that are acceptable. */
  lifecycle_state_t allowed_lc_states[2];
  /** Number of entries in allowed_lc_states. */
  size_t num_allowed_lc_states;
  /** If kHardenedBoolTrue, debug must be disabled (Prod or ProdEnd). */
  hardened_bool_t require_debug_disabled;
  /** Expected attestation public key ID (SHA-256 of pubkey). */
  hmac_digest_t expected_pubkey_id;
  /** Minimum firmware security version. */
  uint32_t min_security_version;
} agent_trust_admission_policy_t;

/**
 * Evaluates the device attestation state against an admission policy.
 *
 * Checks lifecycle state, debug status, attestation key identity, and
 * firmware version. Returns kHardenedBoolTrue only if all policy
 * requirements are satisfied.
 *
 * @param policy The admission policy to evaluate.
 * @param current_identity The current agent host identity.
 * @param current_security_version The firmware security version.
 * @param[out] admitted kHardenedBoolTrue if the device passes admission.
 * @return kErrorOk on success.
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_admission_check(
    const agent_trust_admission_policy_t *policy,
    const agent_trust_identity_t *current_identity,
    uint32_t current_security_version, hardened_bool_t *admitted);

/**
 * Generates a short-lived task token bound to the current attestation state.
 *
 * The token is a keyed HMAC over the device identity, policy version, and a
 * caller-supplied nonce. It can be verified by the control plane to confirm
 * the agent was admitted at a specific point in time.
 *
 * @param identity The current agent host identity.
 * @param nonce A caller-supplied nonce for freshness.
 * @param policy_version Policy version words.
 * @param[out] token The generated task token (SHA-256 HMAC digest).
 * @return kErrorOk on success.
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_task_token_generate(
    const agent_trust_identity_t *identity, const hmac_digest_t *nonce,
    const uint32_t policy_version[kAgentTrustPolicyVersionWords],
    hmac_digest_t *token);

// ---------------------------------------------------------------------------
// Pattern 5: Tamper Response and Quarantine
// ---------------------------------------------------------------------------

/**
 * Tamper event types detectable by the agent trust subsystem.
 */
typedef enum agent_trust_tamper_event {
  /** No tamper event detected. */
  kAgentTrustTamperNone = 0,
  /** Alert handler escalation triggered. */
  kAgentTrustTamperAlertEscalation = 1,
  /** Unexpected lifecycle state transition (e.g. debug re-enabled). */
  kAgentTrustTamperLifecycleAnomaly = 2,
  /** Boot measurement mismatch (integrity failure). */
  kAgentTrustTamperIntegrityFailure = 3,
  /** Sealing policy violated (wrong firmware or owner). */
  kAgentTrustTamperPolicyMismatch = 4,
} agent_trust_tamper_event_t;

/**
 * Tamper status for the agent host.
 */
typedef struct agent_trust_tamper_status {
  /** The most severe tamper event detected. */
  agent_trust_tamper_event_t event;
  /** kHardenedBoolTrue if the device should be quarantined. */
  hardened_bool_t quarantined;
  /** Lifecycle state at the time the tamper was detected. */
  lifecycle_state_t lc_state_at_detection;
  /** Device identifier for the quarantine record. */
  lifecycle_device_id_t device_id;
} agent_trust_tamper_status_t;

/**
 * Checks the device for tamper conditions.
 *
 * Inspects the lifecycle state, alert handler escalation status, and
 * validates boot measurements against expected values. If any anomaly is
 * detected, the status is set accordingly and quarantine is recommended.
 *
 * @param expected_lc_state The expected lifecycle state.
 * @param expected_boot_measurement Expected boot measurement for integrity.
 * @param[out] status The tamper detection result.
 * @return kErrorOk on success (even if a tamper event is detected).
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_tamper_check(
    lifecycle_state_t expected_lc_state,
    const keymgr_binding_value_t *expected_boot_measurement,
    agent_trust_tamper_status_t *status);

/**
 * Responds to a tamper event by disabling the key manager.
 *
 * Disables the key manager (destroying all sideload key slots) and clears
 * any saved attestation keys from OTBN. This is the hardware-backed
 * quarantine primitive: after this call, the device can no longer produce
 * valid attestation signatures or derive secrets.
 *
 * This action is irreversible until the next device reset.
 *
 * @param status The tamper status that triggered the response.
 * @return kErrorOk on success.
 */
OT_WARN_UNUSED_RESULT
rom_error_t agent_trust_quarantine_activate(
    const agent_trust_tamper_status_t *status);

#ifdef __cplusplus
}
#endif

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_AGENT_TRUST_AGENT_TRUST_H_
