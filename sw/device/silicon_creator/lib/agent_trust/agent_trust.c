// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/agent_trust/agent_trust.h"

#include <string.h>

#include "sw/device/lib/base/hardened.h"
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

// ---------------------------------------------------------------------------
// Pattern 1: Hardware Identity for Agent Hosts
// ---------------------------------------------------------------------------

rom_error_t agent_trust_identity_collect(const sc_keymgr_ecc_key_t *key,
                                         agent_trust_identity_t *identity) {
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
  // Hash the entire identity structure to produce a compact identifier.
  hmac_sha256((const uint8_t *)identity, sizeof(agent_trust_identity_t),
              digest);
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
    const agent_trust_seal_policy_t *policy, hardened_bool_t *result) {
  *result = kHardenedBoolFalse;

  // Check lifecycle state matches the required state.
  lifecycle_state_t current_lc_state = lifecycle_state_get();
  if (current_lc_state != policy->required_lc_state) {
    return kErrorOk;
  }

  // Verify attestation binding matches.
  // Compare the current boot measurements against the policy.
  if (memcmp(&boot_measurements.rom_ext, &policy->required_attestation_binding,
             sizeof(keymgr_binding_value_t)) != 0) {
    return kErrorOk;
  }

  // Verify sealing binding matches.
  if (memcmp(&boot_measurements.bl0, &policy->required_sealing_binding,
             sizeof(keymgr_binding_value_t)) != 0) {
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
  // Compute a composite digest: H(provenance || message_digest).
  // This binds the provenance metadata into the signature.
  hmac_digest_t composite_digest;
  hmac_sha256_init();
  hmac_sha256_update((const uint8_t *)provenance,
                     sizeof(agent_trust_provenance_t));
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
 */
static hardened_bool_t lc_state_debug_disabled(lifecycle_state_t state) {
  if (state == kLcStateProd || state == kLcStateProdEnd) {
    return kHardenedBoolTrue;
  }
  return kHardenedBoolFalse;
}

rom_error_t agent_trust_admission_check(
    const agent_trust_admission_policy_t *policy,
    const agent_trust_identity_t *current_identity,
    uint32_t current_security_version, hardened_bool_t *admitted) {
  *admitted = kHardenedBoolFalse;

  // Check lifecycle state is in the allowed set.
  hardened_bool_t lc_allowed = kHardenedBoolFalse;
  for (size_t i = 0; i < policy->num_allowed_lc_states; i++) {
    if (current_identity->lc_state == policy->allowed_lc_states[i]) {
      lc_allowed = kHardenedBoolTrue;
      break;
    }
  }
  if (lc_allowed != kHardenedBoolTrue) {
    return kErrorOk;
  }

  // If required, verify debug is disabled.
  if (policy->require_debug_disabled == kHardenedBoolTrue) {
    if (lc_state_debug_disabled(current_identity->lc_state) !=
        kHardenedBoolTrue) {
      return kErrorOk;
    }
  }

  // Check attestation public key ID matches the expected value.
  if (memcmp(&current_identity->pubkey_id, &policy->expected_pubkey_id,
             sizeof(hmac_digest_t)) != 0) {
    return kErrorOk;
  }

  // Check firmware security version meets the minimum.
  if (current_security_version < policy->min_security_version) {
    return kErrorOk;
  }

  *admitted = kHardenedBoolTrue;
  return kErrorOk;
}

rom_error_t agent_trust_task_token_generate(
    const agent_trust_identity_t *identity, const hmac_digest_t *nonce,
    const uint32_t policy_version[kAgentTrustPolicyVersionWords],
    hmac_digest_t *token) {
  // Generate a task token: H(identity || nonce || policy_version).
  // This binds the token to a specific device state and point in time.
  hmac_sha256_init();
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
    agent_trust_tamper_status_t *status) {
  status->event = kAgentTrustTamperNone;
  status->quarantined = kHardenedBoolFalse;

  // Collect current device state for the tamper record.
  lifecycle_device_id_get(&status->device_id);
  lifecycle_state_t current_lc_state = lifecycle_state_get();
  status->lc_state_at_detection = current_lc_state;

  // Check 1: Lifecycle state anomaly.
  // If the device is not in the expected lifecycle state, this may indicate
  // an attacker has transitioned the device (e.g. re-enabled debug).
  if (current_lc_state != expected_lc_state) {
    status->event = kAgentTrustTamperLifecycleAnomaly;
    status->quarantined = kHardenedBoolTrue;
    return kErrorOk;
  }

  // Check 2: Debug enabled in a production-like state.
  // In Prod/ProdEnd, debug should be disabled. If we are in a non-production
  // state when production was expected, flag it.
  if (expected_lc_state == kLcStateProd ||
      expected_lc_state == kLcStateProdEnd) {
    if (current_lc_state != kLcStateProd &&
        current_lc_state != kLcStateProdEnd) {
      status->event = kAgentTrustTamperLifecycleAnomaly;
      status->quarantined = kHardenedBoolTrue;
      return kErrorOk;
    }
  }

  // Check 3: Boot measurement integrity.
  // Compare the current ROM_EXT measurement against the expected value.
  if (expected_boot_measurement != NULL) {
    if (memcmp(&boot_measurements.rom_ext, expected_boot_measurement,
               sizeof(keymgr_binding_value_t)) != 0) {
      status->event = kAgentTrustTamperIntegrityFailure;
      status->quarantined = kHardenedBoolTrue;
      return kErrorOk;
    }
  }

  return kErrorOk;
}

rom_error_t agent_trust_quarantine_activate(
    const agent_trust_tamper_status_t *status) {
  // Only activate quarantine if the status actually indicates a tamper event.
  if (status->quarantined != kHardenedBoolTrue) {
    return kErrorOk;
  }

  // Clear any saved attestation key from OTBN scratchpad.
  HARDENED_RETURN_IF_ERROR(otbn_boot_attestation_key_clear());

  // Disable the key manager, destroying all sideload key slots.
  // This is irreversible until the next device reset.
  sc_keymgr_disable();

  return kErrorOk;
}
