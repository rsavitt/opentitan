// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_AGENT_TRUST_AGENT_TRUST_TELEMETRY_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_AGENT_TRUST_AGENT_TRUST_TELEMETRY_H_

#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/hardened.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @brief Structured telemetry for the agent trust subsystem.
 *
 * Emits hardware-timestamped events for every security-relevant operation
 * performed by the agent_trust library. Events are stored in an on-device
 * ring buffer and can be drained by the orchestration layer (SWARM) via
 * `agent_trust_telemetry_drain()`. The telemetry bus normalises events
 * against a fixed schema so that the orchestration layer can link them
 * across agents, tasks, and episodes to build a live system-state graph.
 *
 * Design constraints:
 *   - Fixed-size events (no heap allocation).
 *   - Ring buffer overwrites oldest entry when full (bounded memory).
 *   - Timestamps are Ibex MCYCLE values (monotonic, per-reset epoch).
 *   - Events include a sequence number for loss detection.
 *   - All operations are single-threaded (no locking required on Ibex).
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

enum {
  /** Maximum number of events the ring buffer can hold. */
  kAgentTrustTelemetryCapacity = 32,
  /** Size of the event detail payload in 32-bit words. */
  kAgentTrustTelemetryDetailWords = 4,
};

// ---------------------------------------------------------------------------
// Event Types
// ---------------------------------------------------------------------------

/**
 * Agent trust telemetry event types.
 *
 * Each type corresponds to a specific operation in the agent_trust library.
 * The orchestration layer maps these to SWARM schema event classes.
 */
typedef enum agent_trust_telemetry_event_type {
  /** Identity collection completed. */
  kAgentTrustEventIdentityCollect = 0x01,
  /** Identity digest computed. */
  kAgentTrustEventIdentityDigest = 0x02,
  /** Sealing key derivation requested. */
  kAgentTrustEventSealKeyDerive = 0x03,
  /** Sealing policy check completed. */
  kAgentTrustEventSealPolicyCheck = 0x04,
  /** Provenance record built. */
  kAgentTrustEventProvenanceBuild = 0x05,
  /** Provenance signature generated. */
  kAgentTrustEventProvenanceSign = 0x06,
  /** Admission policy evaluated. */
  kAgentTrustEventAdmissionCheck = 0x07,
  /** Task token generated. */
  kAgentTrustEventTaskTokenGenerate = 0x08,
  /** Tamper check performed. */
  kAgentTrustEventTamperCheck = 0x09,
  /** Quarantine activated. */
  kAgentTrustEventQuarantineActivate = 0x0A,
} agent_trust_telemetry_event_type_t;

/**
 * Outcome of a telemetry-emitting operation.
 *
 * Encodes whether the operation succeeded, failed, or produced a
 * security-relevant denial. The orchestration layer uses this to
 * distinguish normal flow from anomalies worth correlating.
 */
typedef enum agent_trust_telemetry_outcome {
  /** Operation succeeded with a positive security decision. */
  kAgentTrustOutcomeAllow = 0x96,
  /** Operation succeeded but the security decision was negative. */
  kAgentTrustOutcomeDeny = 0x69,
  /** Operation returned an error. */
  kAgentTrustOutcomeError = 0x3C,
} agent_trust_telemetry_outcome_t;

// ---------------------------------------------------------------------------
// Event Structure
// ---------------------------------------------------------------------------

/**
 * A single telemetry event emitted by the agent trust subsystem.
 *
 * Fixed-size (48 bytes) to allow ring buffer indexing without fragmentation.
 * The orchestration layer reads these via `agent_trust_telemetry_drain()`
 * and maps them into the SWARM reporting schema.
 */
typedef struct agent_trust_telemetry_event {
  /** Monotonically increasing sequence number (wraps at UINT32_MAX). */
  uint32_t seq;
  /** Ibex MCYCLE timestamp at event emission. */
  uint64_t timestamp_cycles;
  /** Event type identifying the operation. */
  agent_trust_telemetry_event_type_t type;
  /** Outcome of the operation. */
  agent_trust_telemetry_outcome_t outcome;
  /** Lifecycle state at the time of the event. */
  lifecycle_state_t lc_state;
  /** Operation-specific detail words (interpretation depends on type). */
  uint32_t detail[kAgentTrustTelemetryDetailWords];
} agent_trust_telemetry_event_t;

// ---------------------------------------------------------------------------
// Telemetry API
// ---------------------------------------------------------------------------

/**
 * Initialises the telemetry subsystem.
 *
 * Clears the ring buffer and resets the sequence counter. Must be called
 * once during boot before any agent_trust operations are invoked.
 */
void agent_trust_telemetry_init(void);

/**
 * Emits a telemetry event into the ring buffer.
 *
 * Captures the current Ibex MCYCLE timestamp, assigns the next sequence
 * number, and stores the event. If the buffer is full, the oldest event
 * is overwritten (ring semantics).
 *
 * @param type The event type.
 * @param outcome The operation outcome.
 * @param detail Operation-specific detail words (up to 4). Unused slots
 *               should be zero.
 */
void agent_trust_telemetry_emit(agent_trust_telemetry_event_type_t type,
                                agent_trust_telemetry_outcome_t outcome,
                                const uint32_t detail[kAgentTrustTelemetryDetailWords]);

/**
 * Returns the number of unread events in the ring buffer.
 *
 * @return Number of events available for draining.
 */
size_t agent_trust_telemetry_count(void);

/**
 * Drains up to `max_events` telemetry events from the ring buffer.
 *
 * Events are copied into `out` in FIFO order (oldest first). Drained
 * events are removed from the buffer. The orchestration layer should
 * call this periodically to stream events into the telemetry bus.
 *
 * @param[out] out Caller-allocated array to receive events.
 * @param max_events Maximum number of events to drain.
 * @return Number of events actually written to `out`.
 */
size_t agent_trust_telemetry_drain(agent_trust_telemetry_event_t *out,
                                   size_t max_events);

/**
 * Returns the total number of events emitted since the last init,
 * including those that have been overwritten due to ring buffer overflow.
 *
 * The orchestration layer can compare this against the sum of drained
 * events to detect telemetry loss (indicating the drain rate is too
 * slow for the emission rate).
 *
 * @return Total event count since init.
 */
uint32_t agent_trust_telemetry_total_emitted(void);

/**
 * Returns the number of events lost due to ring buffer overflow since
 * the last init.
 *
 * @return Number of overwritten (lost) events.
 */
uint32_t agent_trust_telemetry_overflow_count(void);

#ifdef __cplusplus
}
#endif

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_AGENT_TRUST_AGENT_TRUST_TELEMETRY_H_
