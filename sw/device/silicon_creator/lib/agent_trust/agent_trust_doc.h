// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file
 * @brief Design Notes — Hardware Root of Trust for AI Agent Infrastructure
 *
 * # Overview
 *
 * This library (`agent_trust`) extends OpenTitan's silicon_creator layer
 * with trust primitives purpose-built for AI agent orchestration systems.
 * It bridges the gap between OpenTitan's hardware security mechanisms
 * (DICE, key manager, lifecycle controller, alert handler, OTBN) and the
 * operational requirements of multi-agent platforms such as SWARM.
 *
 * # Problem Statement
 *
 * AI agent systems face a unique trust challenge: agents make high-impact
 * decisions (tool calls, data access, financial transactions, code
 * execution) on behalf of users, often across delegation chains spanning
 * multiple hosts and models. Without hardware-backed identity and
 * attestation, there is no reliable way to:
 *
 *   - Verify that an agent host has not been tampered with
 *   - Bind agent credentials to a specific measured software state
 *   - Produce non-repudiable provenance for agent actions
 *   - Gate sensitive tasks on verified attestation state
 *   - Detect and respond to tampering in real time
 *
 * # Architecture
 *
 * The library is organized into five patterns, each mapping to a specific
 * trust requirement:
 *
 * ## Pattern 1: Hardware Identity (agent_trust_identity_*)
 *
 * Collects the device's DICE-derived identity: device ID, lifecycle
 * state, hardware revision, attestation keypair, and boot measurements.
 * This bundle serves as the agent host's hardware-backed credential that
 * the orchestration layer verifies before admitting the host to the swarm.
 *
 * Key design choices:
 *   - Identity struct is zero-initialized before population to ensure
 *     deterministic hashing (padding bytes must be zero).
 *   - Identity digest hashes fields individually rather than the raw
 *     struct, eliminating compiler-dependent padding non-determinism.
 *
 * ## Pattern 2: Sealed Secrets (agent_trust_seal_*)
 *
 * Derives sealing keys via the key manager, bound to the current boot
 * state. Agent credentials can only be unwrapped on the same device with
 * the same owner chain and (for attestation keys) the same firmware
 * version. Policy checks enforce lifecycle state, binding values, and
 * minimum security version.
 *
 * Key design choices:
 *   - Sealing policy check includes min_security_version enforcement
 *     for anti-rollback protection.
 *   - All binding comparisons use hardened_memeq (constant-time, SCA-
 *     resistant, 32-bit word operations).
 *
 * ## Pattern 3: Signed Provenance (agent_trust_provenance_*)
 *
 * Every high-impact agent action can be signed with a key derived from
 * the device identity, creating a non-repudiable record of who did what,
 * on which hardware, with which software, under which policy.
 *
 * Key design choices:
 *   - Composite digest uses domain separation ("AGTP-SIGN-v1") with
 *     length prefixes: H(tag || len(prov) || prov || len(dig) || dig).
 *     This prevents length-extension attacks and cross-domain collision.
 *   - Provenance records include a format version tag ("AGTP") for
 *     forward compatibility.
 *
 * ## Pattern 4: Policy-Gated Tasks (agent_trust_admission_*, _task_token_*)
 *
 * Before receiving a sensitive task, the agent host must pass an
 * admission check: lifecycle state, debug status, attestation key ID,
 * and firmware version are all verified. On success, a short-lived task
 * token is generated as proof of admission.
 *
 * Key design choices:
 *   - Admission check re-reads lifecycle state from hardware, not from
 *     the caller-supplied identity struct (TOCTOU defense).
 *   - Task tokens use HMAC-SHA256 with a caller-provided key (should be
 *     keymgr-derived), not unkeyed SHA-256.
 *   - num_allowed_lc_states is bounds-checked against the array size.
 *
 * ## Pattern 5: Tamper Response (agent_trust_tamper_*, _quarantine_*)
 *
 * Checks lifecycle state, boot measurement integrity, and caller-reported
 * alert handler escalation status. On anomaly, recommends quarantine.
 * Quarantine activation disables the key manager and clears OTBN keys —
 * an irreversible action that prevents the device from producing valid
 * attestation or deriving secrets until the next reset.
 *
 * Key design choices:
 *   - Alert handler escalation is passed as a parameter (not read
 *     directly) because the silicon_creator alert driver has no
 *     escalation-state query API. The caller reads it via their
 *     platform-specific interface (e.g. dif_alert_handler).
 *
 * # Security Hardening
 *
 * All security-critical paths follow OpenTitan's hardening conventions:
 *
 *   - **Constant-time comparisons**: hardened_memeq() for all secret/
 *     binding/key comparisons. Resists timing side-channels and
 *     single-glitch fault bypass.
 *   - **Fault injection resistance**: Every security decision branch
 *     uses launder32() + HARDENED_CHECK_EQ/NE. An attacker must glitch
 *     both the branch and the redundant check.
 *   - **TOCTOU defense**: Lifecycle state is re-read from hardware at
 *     the point of use, not cached from an earlier call.
 *   - **Bounds checking**: Array indices are clamped before use.
 *   - **Domain separation**: Cryptographic operations include unique
 *     prefixes to prevent cross-context collision reuse.
 *
 * # Telemetry Integration (SWARM)
 *
 * The telemetry subsystem (`agent_trust_telemetry`) emits a structured
 * event for every security-relevant operation. Events are stored in a
 * fixed-capacity ring buffer (32 entries, ~1.5 KiB) with:
 *
 *   - Monotonic sequence number (loss detection)
 *   - Ibex MCYCLE timestamp (latency measurement)
 *   - Event type and outcome (allow/deny/error)
 *   - Lifecycle state at emission time
 *   - 4 words of operation-specific detail
 *
 * The orchestration layer drains events via agent_trust_telemetry_drain()
 * and maps them into SWARM's reporting schema, linking across agents,
 * tasks, and episodes to build a live system-state graph. This enables
 * detection of:
 *
 *   - Unstable routing (repeated admission denials from same host)
 *   - Adversarial delegation (tamper events correlated with delegation)
 *   - Cascading coordination failures (quarantine propagation patterns)
 *
 * # Dependencies
 *
 * This library depends on the following OpenTitan silicon_creator APIs:
 *
 *   - sw/device/silicon_creator/lib/drivers/keymgr (key derivation)
 *   - sw/device/silicon_creator/lib/drivers/lifecycle (state queries)
 *   - sw/device/silicon_creator/lib/drivers/hmac (SHA-256, HMAC)
 *   - sw/device/silicon_creator/lib/otbn_boot_services (ECDSA signing)
 *   - sw/device/silicon_creator/lib/base/boot_measurements (integrity)
 *   - sw/device/lib/base/hardened_memory (constant-time operations)
 *   - sw/device/silicon_creator/lib/drivers/ibex (cycle timestamps)
 */
