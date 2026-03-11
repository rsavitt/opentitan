// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/agent_trust/agent_trust.h"

#include <string.h>

#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/base/hardened_memory.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/silicon_creator/lib/base/boot_measurements.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/device/silicon_creator/lib/drivers/keymgr.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/otbn_boot_services.h"

// Provenance record format tag: "AGTP" (Agent Trust Provenance).
static const uint8_t kProvenanceTag[kAgentTrustProvenanceTagBytes] = {
    'A', 'G', 'T', 'P'};

// Domain separation prefix for provenance signing.
static const uint8_t kProvenanceSignDomainSep[] = "AGTP-SIGN-v1";

// ---------------------------------------------------------------------------
// Pattern 1: Hardware Identity for Agent Hosts
// ---------------------------------------------------------------------------

rom_error_t agent_trust_identity_collect(const sc_keymgr_ecc_key_t *key,
                                         agent_trust_identity_t *identity) {
  // Fix #7: Zero-initialize to eliminate non-determinism from padding bytes.
  memset(identity, 0, sizeof(agent_trust_identity_t));

  // Collect device identifier from OTP.
  lifecycle_device_id_get(&identity->device_id);

  // Collect lifecycle state.
  identity->lc_state = lifecycle_state_get();

  // Collect hardware revision.
  lifecycle_hw_rev_get(&identity->hw_rev);

  // Copy boot measurements into the identity structure.
  memcpy(&identity->rom_ext_measurement, &boot_measurements.rom_ext,
         sizeof(keymgr_binding_value_t));
  memcpy(&identity->bl0_measurement, &boot_measurements.bl0,
         sizeof(keymgr_binding_value_t));

  // Generate the DICE attestation keypair via keymgr + OTBN.
  // The key manager must already be advanced to the required stage.
  HARDENED_RETURN_IF_ERROR(sc_keymgr_state_check(key->required_keymgr_state));
  HARDENED_RETURN_IF_ERROR(
      otbn_boot_cert_ecc_p256_keygen(*key, &identity->pubkey_id,
                                     &identity->pubkey));

  return kErrorOk;
}

rom_error_t agent_trust_identity_digest(
    const agent_trust_identity_t *identity, hmac_digest_t *digest) {
  // Fix #7: Hash individual fields to avoid padding-byte non-determinism.
  hmac_sha256_init();
  hmac_sha256_update(&identity->device_id, sizeof(identity->device_id));
  hmac_sha256_update(&identity->lc_state, sizeof(identity->lc_state));
  hmac_sha256_update(&identity->hw_rev, sizeof(identity->hw_rev));
  hmac_sha256_update(&identity->pubkey, sizeof(identity->pubkey));
  hmac_sha256_update(&identity->pubkey_id, sizeof(identity->pubkey_id));
  hmac_sha256_update(&identity->rom_ext_measurement,
                     sizeof(identity->rom_ext_measurement));
  hmac_sha256_update(&identity->bl0_measurement,
                     sizeof(identity->bl0_measurement));
  hmac_sha256_process();
  hmac_sha256_final(digest);
  return kErrorOk;
}

// ---------------------------------------------------------------------------
// Pattern 2: Seal Agent Secrets to Approved Software State
// ---------------------------------------------------------------------------

rom_error_t agent_trust_seal_key_derive(
    sc_keymgr_diversification_t diversification,
    sc_keymgr_key_type_t key_type, sc_keymgr_dest_t dest) {
  return sc_keymgr_generate_key(dest, key_type, diversification);
}

rom_error_t agent_trust_seal_policy_check(
    const agent_trust_seal_policy_t *policy, uint32_t current_security_version,
    hardened_bool_t *result) {
  *result = kHardenedBoolFalse;

  // Fix #2: Hardened lifecycle state comparison with launder32.
  lifecycle_state_t current_lc_state = lifecycle_state_get();
  if (launder32(current_lc_state) != policy->required_lc_state) {
    return kErrorOk;
  }
  HARDENED_CHECK_EQ(current_lc_state, policy->required_lc_state);

  // Fix #1: Constant-time comparison for attestation binding.
  hardened_bool_t attest_match = hardened_memeq(
      boot_measurements.rom_ext.data,
      policy->required_attestation_binding.data,
      ARRAYSIZE(policy->required_attestation_binding.data));
  if (launder32(attest_match) != kHardenedBoolTrue) {
    return kErrorOk;
  }
  HARDENED_CHECK_EQ(attest_match, kHardenedBoolTrue);

  // Fix #1: Constant-time comparison for sealing binding.
  hardened_bool_t seal_match = hardened_memeq(
      boot_measurements.bl0.data,
      policy->required_sealing_binding.data,
      ARRAYSIZE(policy->required_sealing_binding.data));
  if (launder32(seal_match) != kHardenedBoolTrue) {
    return kErrorOk;
  }
  HARDENED_CHECK_EQ(seal_match, kHardenedBoolTrue);

  // Fix #8: Check minimum security version (was missing).
  if (launder32(current_security_version) < policy->min_security_version) {
    return kErrorOk;
  }

  *result = kHardenedBoolTrue;
  return kErrorOk;
}

// ---------------------------------------------------------------------------
// Pattern 3: Signed Provenance for Agent Actions
// ---------------------------------------------------------------------------

rom_error_t agent_trust_provenance_build(
    const uint8_t *workload_id, size_t workload_id_len,
    const uint32_t policy_version[kAgentTrustPolicyVersionWords],
    const keymgr_binding_value_t *boot_measurement,
    agent_trust_provenance_t *provenance) {
  // Set the format tag.
  memcpy(provenance->tag, kProvenanceTag, kAgentTrustProvenanceTagBytes);

  // Collect device identity.
  lifecycle_device_id_get(&provenance->device_id);
  provenance->lc_state = lifecycle_state_get();

  // Hash the workload identity into a fixed-size digest.
  hmac_sha256(workload_id, workload_id_len, &provenance->workload_id_digest);

  // Copy boot measurement and policy version.
  memcpy(&provenance->boot_measurement, boot_measurement,
         sizeof(keymgr_binding_value_t));
  memcpy(provenance->policy_version, policy_version,
         sizeof(uint32_t) * kAgentTrustPolicyVersionWords);

  return kErrorOk;
}

rom_error_t agent_trust_provenance_sign(
    const agent_trust_provenance_t *provenance,
    const hmac_digest_t *message_digest, ecdsa_p256_signature_t *sig) {
  // Fix #6: Domain-separated composite digest.
  // H(domain_sep || len(provenance) || provenance || len(digest) || digest)
  // This prevents length-extension attacks and cross-domain collision reuse.
  hmac_digest_t composite_digest;
  uint32_t provenance_len = (uint32_t)sizeof(agent_trust_provenance_t);
  uint32_t digest_len = (uint32_t)sizeof(hmac_digest_t);

  hmac_sha256_init();
  hmac_sha256_update(kProvenanceSignDomainSep,
                     sizeof(kProvenanceSignDomainSep));
  hmac_sha256_update(&provenance_len, sizeof(provenance_len));
  hmac_sha256_update((const uint8_t *)provenance,
                     sizeof(agent_trust_provenance_t));
  hmac_sha256_update(&digest_len, sizeof(digest_len));
  hmac_sha256_update((const uint8_t *)message_digest, sizeof(hmac_digest_t));
  hmac_sha256_process();
  hmac_sha256_final(&composite_digest);

  // Sign the composite digest using the previously saved attestation key.
  return otbn_boot_attestation_endorse(&composite_digest, sig);
}

// ---------------------------------------------------------------------------
// Pattern 4: Policy-Gated Task Execution
// ---------------------------------------------------------------------------

/**
 * Helper: check if a lifecycle state indicates debug is disabled.
 *
 * Debug is considered disabled in Prod and ProdEnd states.
 * Uses hardened comparisons to resist fault injection.
 */
static hardened_bool_t lc_state_debug_disabled(lifecycle_state_t state) {
  if (launder32(state) == kLcStateProd) {
    HARDENED_CHECK_EQ(state, kLcStateProd);
    return kHardenedBoolTrue;
  }
  if (launder32(state) == kLcStateProdEnd) {
    HARDENED_CHECK_EQ(state, kLcStateProdEnd);
    return kHardenedBoolTrue;
  }
  return kHardenedBoolFalse;
}

rom_error_t agent_trust_admission_check(
    const agent_trust_admission_policy_t *policy,
    const agent_trust_identity_t *current_identity,
    uint32_t current_security_version, hardened_bool_t *admitted) {
  *admitted = kHardenedBoolFalse;

  // Fix #3: Re-read lifecycle state directly from hardware rather than
  // trusting the caller-supplied identity struct. An attacker who controls
  // memory could forge the lc_state field.
  lifecycle_state_t hw_lc_state = lifecycle_state_get();

  // Cross-check: hardware state must match the identity struct's claim.
  // If they differ, the identity is stale or forged.
  if (launder32(hw_lc_state) != current_identity->lc_state) {
    return kErrorOk;
  }
  HARDENED_CHECK_EQ(hw_lc_state, current_identity->lc_state);

  // Fix #9: Clamp num_allowed_lc_states to prevent out-of-bounds read.
  size_t num_states = policy->num_allowed_lc_states;
  if (num_states > kAgentTrustMaxAllowedLcStates) {
    return kErrorOk;
  }

  // Check lifecycle state is in the allowed set.
  // Fix #2: Use launder32 on the comparison to resist glitch skip.
  hardened_bool_t lc_allowed = kHardenedBoolFalse;
  for (size_t i = 0; i < num_states; i++) {
    if (launder32(hw_lc_state) == policy->allowed_lc_states[i]) {
      lc_allowed = kHardenedBoolTrue;
      break;
    }
  }
  if (launder32(lc_allowed) != kHardenedBoolTrue) {
    return kErrorOk;
  }
  HARDENED_CHECK_EQ(lc_allowed, kHardenedBoolTrue);

  // If required, verify debug is disabled.
  if (launder32(policy->require_debug_disabled) == kHardenedBoolTrue) {
    HARDENED_CHECK_EQ(policy->require_debug_disabled, kHardenedBoolTrue);
    hardened_bool_t debug_off = lc_state_debug_disabled(hw_lc_state);
    if (launder32(debug_off) != kHardenedBoolTrue) {
      return kErrorOk;
    }
    HARDENED_CHECK_EQ(debug_off, kHardenedBoolTrue);
  }

  // Fix #1: Constant-time comparison for attestation public key ID.
  hardened_bool_t pubkey_match = hardened_memeq(
      current_identity->pubkey_id.digest, policy->expected_pubkey_id.digest,
      ARRAYSIZE(policy->expected_pubkey_id.digest));
  if (launder32(pubkey_match) != kHardenedBoolTrue) {
    return kErrorOk;
  }
  HARDENED_CHECK_EQ(pubkey_match, kHardenedBoolTrue);

  // Check firmware security version meets the minimum.
  if (launder32(current_security_version) < policy->min_security_version) {
    return kErrorOk;
  }

  *admitted = kHardenedBoolTrue;
  return kErrorOk;
}

rom_error_t agent_trust_task_token_generate(
    hmac_key_t key, const agent_trust_identity_t *identity,
    const hmac_digest_t *nonce,
    const uint32_t policy_version[kAgentTrustPolicyVersionWords],
    hmac_digest_t *token) {
  // Fix #5: Use HMAC-SHA256 (keyed) instead of plain SHA-256.
  // Without a key, anyone who knows the identity and nonce can forge tokens.
  sc_hmac_hmac_sha256_init(key, /*big_endian_digest=*/false);
  hmac_sha256_update((const uint8_t *)identity,
                     sizeof(agent_trust_identity_t));
  hmac_sha256_update((const uint8_t *)nonce, sizeof(hmac_digest_t));
  hmac_sha256_update((const uint8_t *)policy_version,
                     sizeof(uint32_t) * kAgentTrustPolicyVersionWords);
  hmac_sha256_process();
  hmac_sha256_final(token);
  return kErrorOk;
}

// ---------------------------------------------------------------------------
// Pattern 5: Tamper Response and Quarantine
// ---------------------------------------------------------------------------

rom_error_t agent_trust_tamper_check(
    lifecycle_state_t expected_lc_state,
    const keymgr_binding_value_t *expected_boot_measurement,
    hardened_bool_t alert_escalation_detected,
    agent_trust_tamper_status_t *status) {
  status->event = kAgentTrustTamperNone;
  status->quarantined = kHardenedBoolFalse;

  // Collect current device state for the tamper record.
  lifecycle_device_id_get(&status->device_id);
  lifecycle_state_t current_lc_state = lifecycle_state_get();
  status->lc_state_at_detection = current_lc_state;

  // Fix #10: Check caller-provided alert escalation status.
  // The caller reads the alert handler state using their platform-specific
  // interface (e.g. dif_alert_handler_get_class_state) and passes it here.
  if (launder32(alert_escalation_detected) == kHardenedBoolTrue) {
    HARDENED_CHECK_EQ(alert_escalation_detected, kHardenedBoolTrue);
    status->event = kAgentTrustTamperAlertEscalation;
    status->quarantined = kHardenedBoolTrue;
    return kErrorOk;
  }

  // Check 1: Lifecycle state anomaly.
  // Fix #2 + #4: Single hardened check (removed dead Check 2).
  if (launder32(current_lc_state) != expected_lc_state) {
    status->event = kAgentTrustTamperLifecycleAnomaly;
    status->quarantined = kHardenedBoolTrue;
    return kErrorOk;
  }
  HARDENED_CHECK_EQ(current_lc_state, expected_lc_state);

  // Check 2: Boot measurement integrity.
  // Fix #1: Use constant-time hardened_memeq instead of memcmp.
  if (expected_boot_measurement != NULL) {
    hardened_bool_t boot_match = hardened_memeq(
        boot_measurements.rom_ext.data, expected_boot_measurement->data,
        ARRAYSIZE(expected_boot_measurement->data));
    if (launder32(boot_match) != kHardenedBoolTrue) {
      status->event = kAgentTrustTamperIntegrityFailure;
      status->quarantined = kHardenedBoolTrue;
      return kErrorOk;
    }
    HARDENED_CHECK_EQ(boot_match, kHardenedBoolTrue);
  }

  return kErrorOk;
}

rom_error_t agent_trust_quarantine_activate(
    const agent_trust_tamper_status_t *status) {
  // Only activate quarantine if the status actually indicates a tamper event.
  // Fix #2: Hardened check on the quarantine decision.
  if (launder32(status->quarantined) != kHardenedBoolTrue) {
    return kErrorOk;
  }
  HARDENED_CHECK_EQ(status->quarantined, kHardenedBoolTrue);

  // Clear any saved attestation key from OTBN scratchpad.
  HARDENED_RETURN_IF_ERROR(otbn_boot_attestation_key_clear());

  // Disable the key manager, destroying all sideload key slots.
  // This is irreversible until the next device reset.
  sc_keymgr_disable();

  return kErrorOk;
}
