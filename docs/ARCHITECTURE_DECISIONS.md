# Heavy Duty Zig — Architecture Decisions

Updated: 2026-10-07

This document records significant architectural decisions for Heavy Duty Zig (HDZ).
It is not a changelog. Small implementation details do not belong here.

The purpose is continuity: future work should be able to answer not only *what* the
architecture is, but *why* it was chosen.

## Working principle

**Protocol layers report facts. Higher layers assign diagnostic meaning.**

HDZ is truck-side diagnostics infrastructure first. Current work is J1708/J1587
capture ingestion. Active requests, clears, programming, and service actions remain
out of scope unless explicitly supported and proven safe.

---

## AD-001 — Keep J1708 validity separate from storage policy

**Status:** Accepted

### Decision

Whether a byte sequence is valid J1708 must not depend on how much storage a
particular consumer has chosen to reserve.

J1708's normal operating limit of 21 bytes must not be encoded as a universal
protocol maximum. Longer messages are permitted by J1708 under certain vehicle
conditions.

### Why

HDZ is intended to remain useful across different environments:

- desktop capture analyzer → allocator-backed or large storage is acceptable;
- RP1210 application → practical API-sized buffers may already exist;
- embedded device → caller-selected bounded storage may be necessary.

These environments have different memory policies, but they should agree on what
constitutes valid J1708.

### Implications

- A valid J1708 frame is not invalid merely because it exceeds 21 bytes.
- A storage limit failure is distinct from a protocol validity failure.
- Future ownership forms may use different capacities without changing protocol
  semantics.

---

## AD-002 — `FrameView` is the protocol-level J1708 representation

**Status:** Accepted

### Decision

`j1708.FrameView` is a borrowed view of one externally delimited, checksum-valid
J1708 message.

It validates only what can be established from the supplied byte range.

### Guarantees

A `FrameView` guarantees:

- at least MID + checksum are present;
- the supplied byte range is treated as one externally established message;
- the J1708 checksum is valid;
- the first byte is available as MID;
- the final byte is available as checksum.

### Non-guarantees

A `FrameView` does **not** guarantee:

- how the physical frame boundary was discovered;
- that the frame is 21 bytes or shorter;
- that a longer transmission was legal under the vehicle's operating conditions;
- that the payload is J1587;
- that J1587 contents are structurally valid;
- ownership of the underlying bytes;
- capture timestamp, record number, logger identity, or provenance.

### Why

Checksum validity alone cannot establish physical J1708 boundaries. Two valid
frames concatenated together also sum to a valid checksum.

The caller or an earlier recovery/transport layer must establish the candidate
boundary before constructing the view.

---

## AD-003 — Owned frame storage is a separate policy

**Status:** Accepted

### Decision

`j1708.BoundedFrame(N)` owns a copy of a valid frame using caller-selected,
compile-time bounded storage.

### Required behavior

If the frame is valid J1708 but does not fit in `N`, the result is a storage
failure such as `CapacityExceeded`, not an invalid-J1708 result.

### Why

This preserves a zero-allocation path for embedded or bounded consumers without
making their memory budget part of the protocol definition.

### Future direction

An allocator-backed owner may be added later for desktop analysis. It is not
required merely to continue Milestone 5.

---

## AD-004 — Capture metadata stays outside J1708 protocol types

**Status:** Accepted

### Decision

Timestamps, logger record numbers, source-file information, adapter identity, and
similar capture metadata do not belong inside `FrameView` or the underlying J1708
frame representation.

### Why

Those facts describe how a frame was observed, not the J1708 message itself.
Different transports will have different metadata semantics.

A future captured-frame wrapper may combine protocol data with source metadata,
but the base protocol type remains transport-independent.

---

## AD-005 — Recover frame boundaries conservatively

**Status:** Accepted

### Decision

When a capture source has lost the original physical J1708 idle timing, recovery
evaluates complete interpretations of the entire byte chunk.

Recovery status is determined by the number of complete surviving
interpretations:

- exactly **1** → `recovered`
- **2 or more** → `ambiguous`
- **0** → `unrecoverable`

### Definition

An interpretation is one complete explanation of the whole chunk as a sequence of
candidate J1708 frames.

A single bad frame invalidates that interpretation.

### Why

A checksum-zero prefix is useful evidence, but not proof of a physical boundary.
A concatenation of checksum-valid frames is itself checksum-valid.

### Implementation consequence

The recovery search only needs to distinguish:

- none;
- one;
- multiple.

It does not need to enumerate every possible interpretation once two complete
interpretations have survived.

Caller-provided scratch storage is used so the algorithm does not require a heap.

---

## AD-006 — Candidate recovery evidence must not depend on HDZ feature support

**Status:** Accepted

### Decision

A candidate frame must satisfy J1708 properties that are provable from the bytes.

For J1587-reserved MIDs, known J1587 structural contradictions may eliminate a
candidate. Unsupported or not-yet-understood syntax must not be treated as proof
that the frame boundary is impossible.

### Rule

Lack of understanding is not evidence of invalidity.

### Specifically excluded as recovery evidence

Do not prefer or reject a boundary based on:

- whether HDZ supports the PID;
- whether the parameter is diagnostically useful;
- whether the MID is familiar;
- whether the payload would produce a desired observation;
- whether a decoded value merely "looks reasonable";
- whether the frame exceeds 21 bytes.

---

## AD-007 — J1587 structural inspection distinguishes invalid from unknown

**Status:** Accepted

### Decision

J1587 structural inspection uses these outcomes:

- `not_j1587` — the MID is outside the J1587 range;
- `valid` — known syntax consumes the frame cleanly;
- `invalid` — known rules prove the structure cannot be complete;
- `unknown` — HDZ does not know enough to judge the structure safely.

### Recovery treatment

- `valid` → candidate survives;
- `not_j1587` → candidate survives;
- `unknown` → candidate survives conservatively;
- `invalid` → candidate is rejected.

### Why

Unsupported protocol space must not silently become malformed traffic.

---

## AD-008 — `parameters.zig` is the canonical J1587 parameter-boundary implementation

**Status:** Accepted

### Decision

`src/j1587/parameters.zig` owns the canonical rules for walking parameters inside
one J1708/J1587 frame.

It supports multiple parameters per frame rather than assuming one frame equals
one parameter.

The structural inspector delegates to this iterator rather than maintaining a
second copy of the PID-length/page grammar.

### Why

Authentic traffic demonstrated that one J1708 frame can contain several J1587
parameters, including fixed-length and variable-length parameters.

Duplicating the grammar in both structural validation and parameter iteration
would create drift risk.

### Current parameter representation

A parsed parameter carries:

- source MID;
- normalized PID (`u16`, including later pages);
- borrowed data;
- parameter kind where needed.

Unsupported page-two or later PIDs are valid protocol observations even when HDZ
does not decode their semantics.

---

## AD-009 — PID 192 reassembly consumes parsed parameter data

**Status:** Accepted

### Decision

The PID 192 multisection bank exposes a data-level entry point equivalent to:

`pushData(source_mid, data)`

The older raw-message `push(...)` path remains as a compatibility wrapper.

### Why

Multisection reassembly should operate on the logical PID 192 parameter once
J1587 framing has already been parsed. It should not require a synthetic
one-parameter pseudo-message representation.

This allows the pipeline to become:

J1708 frame → J1587 parameter iterator → PID 192 data → reassembly.

---

## AD-010 — The stateful J1587 decoder consumes logical parameters

**Status:** Accepted

### Decision

`j1587.Decoder` now has a parameter-level entry point and can consume a parsed
J1587 `Parameter`.

The previous raw pseudo-message entry point is retained for compatibility and
existing tests.

### Decoder responsibilities

The decoder owns:

- PID 192 reassembly;
- supported observation routing;
- unsupported-parameter metadata;
- observation lifetime enforcement.

It does not need to rediscover parameter boundaries already established by the
J1587 iterator.

### PID width

Unsupported metadata uses `u16` PIDs so later-page J1587 parameters remain valid
but unsupported rather than being treated as malformed.

---

## AD-011 — Observation consumption must interleave with parameter consumption

**Status:** Accepted

### Decision

A single J1708 frame may contain multiple J1587 parameters, but the existing
stateful decoder requires observations from a supported parameter to be drained
before another parameter is pushed.

The decoder's `ObservationsPending` rule remains meaningful.

### Correct flow

1. get the next parameter from the frame;
2. push it into the decoder;
3. if unsupported or pending, continue;
4. if ready, call `Decoder.next()` until it returns `null`;
5. only then push the next parameter.

### Why

Observations borrow caller or reassembly storage. Interleaving preserves the
existing lifetime contract and avoids silently invalidating borrowed data.

---

## AD-012 — Do not make the decoder own frame iteration prematurely

**Status:** Accepted

### Decision

Do not immediately add a `Decoder.pushFrame()` loop that internally walks every
parameter in a frame.

Frame iteration and parameter decoding remain separate responsibilities for now.

### Why

If the decoder owned frame iteration, it would have to suspend midway through a
borrowed `FrameView` whenever observations became pending. That would create a new
cross-call lifetime/state responsibility inside the decoder.

Keeping the layers separate currently gives a clearer composition:

J1708 `FrameView`
→ J1587 `ParameterIterator`
→ one logical `Parameter`
→ stateful `Decoder`
→ typed observation(s)

---

## AD-013 — External research captures are validation inputs, not bundled fixtures by default

**Status:** Accepted

### Decision

External captures without clear redistribution permission may be used locally for
validation but are not copied into the repository.

Permanent regression tests should use synthetic byte sequences that exercise the
same protocol behavior.

### Why

The current public J1708 research corpus used during Milestone 5 does not provide
a license that safely permits bundling its captures into HDZ.

The project should preserve reproducibility without silently relicensing research
data.

---

# Current Milestone 5 architecture

The current intended flow is:

```text
external capture format
        ↓
capture adapter
        ↓
raw byte chunk
        ↓
conservative frame recovery
        ↓
J1708 FrameView(s)
        ↓
J1587 ParameterIterator
        ↓
logical Parameter
        ↓
stateful J1587 Decoder
        ├── PID 192 reassembly
        ├── PID 194 diagnostics
        ├── PID 243 identity
        └── other supported observations
        ↓
typed protocol observations
```

The capture adapter, recovery logic, protocol framing, parameter parsing, decoding,
and higher-level diagnostic meaning remain separate layers.

---

# Current implementation checkpoints

As of this update:

- `FrameView` exists and validates externally delimited checksum-valid J1708 bytes.
- `BoundedFrame(N)` exists and owns a bounded copy without redefining J1708 validity.
- frame recovery classifies chunks as recovered, ambiguous, or unrecoverable;
- a recovered result can walk the unique surviving sequence of `FrameView`s;
- recovery has been validated locally against an authentic concatenated J1708
  logger record, without retaining that external byte sequence in the repository;
- `parameters.zig` walks multiple J1587 parameters in one frame;
- `structure.zig` delegates to the parameter iterator;
- PID 192 reassembly accepts parsed parameter data;
- `Decoder.pushParameter(...)` accepts logical J1587 parameters;
- multiple parameters from one J1708 frame have been composed successfully with
  the stateful decoder;
- `FrameCursor` exposes observations and unsupported-parameter metadata while
  hiding internal pending bookkeeping;
- a shared decoder preserves PID 192 multisection state across separate J1708
  frames;
- package tests are green at this checkpoint.

---

## AD-014 — Frame-level orchestration exposes useful events, not bookkeeping

**Status:** Accepted

### Decision

`j1587.FrameCursor` walks one J1708 frame, feeds each parsed J1587 parameter into
a shared stateful decoder, and exposes only caller-useful events.

Its public event stream currently includes:

- typed observations;
- unsupported-parameter metadata.

Internal decoder `.pending` state, including an incomplete PID 192 transfer, does
not produce a public event by itself.

### Why

Unsupported parameters are still evidence and should not disappear merely because
HDZ does not decode them yet.

By contrast, a temporary PID 192 pending state is reassembly bookkeeping rather
than a completed diagnostic fact.

### Lifetime and state consequence

`FrameCursor` borrows a `Decoder`; it does not own one.

That shared decoder may outlive any single physical J1708 frame so multisection
state can continue across frame boundaries.

This behavior is now covered by a synthetic cross-frame test in which one PID 192
section arrives in the first J1708 frame and the completing section arrives in the
second. The resulting logical parameter is decoded only after reassembly completes.

### Resulting flow

```text
J1708 FrameView
    ↓
FrameCursor
    ↓
ParameterIterator
    ↓
Decoder.pushParameter()
    ├── pending      → emit nothing
    ├── unsupported  → Event.unsupported_parameter
    └── ready        → drain Decoder.next()
                           ↓
                       Event.observation
```

Physical J1708 frame boundaries therefore do not interrupt logical J1587
multisection decoding.

---

# Open architecture questions

None recorded at this checkpoint.

---

# Decision discipline

When a future change conflicts with an accepted decision here:

1. do not silently work around the decision;
2. identify the conflict;
3. decide whether the old decision is still correct;
4. if it changes, update this document with the new decision and rationale.

When prior project context is uncertain, use the project's **Acknowledge Gap**
practice:

- state what is already known or settled;
- state what is unknown or missing;
- distinguish new reasoning or newly discovered evidence from prior established
  conclusions.
