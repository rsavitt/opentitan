// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/agent_trust/agent_trust_telemetry.h"

#include <string.h>

#include "sw/device/silicon_creator/lib/drivers/ibex.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"

// ---------------------------------------------------------------------------
// Ring Buffer State
// ---------------------------------------------------------------------------

/**
 * Ring buffer storing telemetry events.
 *
 * - `head` is the index of the next slot to write.
 * - `count` is the number of valid (unread) events in the buffer.
 * - `read_idx` is the index of the oldest unread event.
 *
 * When count == capacity, a new emit overwrites the oldest event and
 * advances read_idx.
 */
static struct {
  agent_trust_telemetry_event_t events[kAgentTrustTelemetryCapacity];
  size_t head;
  size_t read_idx;
  size_t count;
  uint32_t next_seq;
  uint32_t total_emitted;
  uint32_t overflow_count;
} telemetry_state;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

void agent_trust_telemetry_init(void) {
  memset(&telemetry_state, 0, sizeof(telemetry_state));
}

void agent_trust_telemetry_emit(
    agent_trust_telemetry_event_type_t type,
    agent_trust_telemetry_outcome_t outcome,
    const uint32_t detail[kAgentTrustTelemetryDetailWords]) {
  agent_trust_telemetry_event_t *slot =
      &telemetry_state.events[telemetry_state.head];

  slot->seq = telemetry_state.next_seq++;
  slot->timestamp_cycles = ibex_mcycle();
  slot->type = type;
  slot->outcome = outcome;
  slot->lc_state = lifecycle_state_get();

  if (detail != NULL) {
    memcpy(slot->detail, detail, sizeof(slot->detail));
  } else {
    memset(slot->detail, 0, sizeof(slot->detail));
  }

  // Advance the write head (ring wrap).
  telemetry_state.head =
      (telemetry_state.head + 1) % kAgentTrustTelemetryCapacity;

  if (telemetry_state.count < kAgentTrustTelemetryCapacity) {
    telemetry_state.count++;
  } else {
    // Buffer full: overwrite oldest, advance read pointer.
    telemetry_state.read_idx =
        (telemetry_state.read_idx + 1) % kAgentTrustTelemetryCapacity;
    telemetry_state.overflow_count++;
  }

  telemetry_state.total_emitted++;
}

size_t agent_trust_telemetry_count(void) {
  return telemetry_state.count;
}

size_t agent_trust_telemetry_drain(agent_trust_telemetry_event_t *out,
                                   size_t max_events) {
  size_t drained = 0;
  while (drained < max_events && telemetry_state.count > 0) {
    memcpy(&out[drained],
           &telemetry_state.events[telemetry_state.read_idx],
           sizeof(agent_trust_telemetry_event_t));
    telemetry_state.read_idx =
        (telemetry_state.read_idx + 1) % kAgentTrustTelemetryCapacity;
    telemetry_state.count--;
    drained++;
  }
  return drained;
}

uint32_t agent_trust_telemetry_total_emitted(void) {
  return telemetry_state.total_emitted;
}

uint32_t agent_trust_telemetry_overflow_count(void) {
  return telemetry_state.overflow_count;
}
