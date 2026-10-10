# Heavy Duty Zig — Architecture Decisions

Updated: 2026-10-09

This document records significant architectural decisions for Heavy Duty Zig (HDZ).
It is not a changelog. Small implementation details do not belong here.

The purpose is continuity: future work should be able to answer not only *what* the
architecture is, but *why* it was chosen.

## Working principle

**Protocol layers report facts. Higher layers assign diagnostic meaning.**

HDZ is truck-side diagnostics infrastructure first. Current work is passive
diagnostic evidence collection, correlation, and inventory across J1708/J1587,
J1939, and observed ISO-TP/UDS traffic. Active requests, clears, programming,
and service actions remain out of scope unless explicitly supported and proven
safe.

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

## Milestone 5 status

**Complete.**

Milestone 5 established and authentically validated the file-backed J1708/J1587
ingestion pipeline from external capture text through conservative recovery and
typed diagnostic observations.

The milestone does not include live vehicle acquisition, waveform decoding,
complete PID coverage, or active diagnostics. Those remain future work.

# Milestone 5 architecture

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
- `capture_text` converts logger text into caller-owned record bytes without
  claiming those records are already J1708 frame boundaries;
- malformed capture lines are preserved as rejected audit entries instead of
  aborting the remainder of the file;
- `CaptureCursor` fully drains a recovered record before allowing capture byte
  storage to be reused for the next record;
- recovered J1708 frames that are not J1587 are preserved as caller-visible
  evidence rather than treated as capture failures;
- the complete file-backed pipeline has been validated against 308 authentic
  logger records; detailed empirical results are recorded in
  `docs/AUTHENTIC_CAPTURE_VALIDATION.md`;
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

## AD-015 — Capture records are transport evidence, not J1708 frame claims

**Status:** Accepted

### Decision

`capture_text` is responsible for converting supported logger text into raw record
bytes and preserving source-line identity.

A parsed capture record is not automatically a `j1708.FrameView`.

### Why

Authentic logger records may contain:

- one physical J1708 frame;
- multiple concatenated J1708 frames;
- byte sequences whose original physical boundaries cannot be reconstructed
  uniquely after the logger discards bus idle timing.

The capture adapter therefore reports what the logger retained and leaves frame
recovery to the recovery layer.

### Storage consequence

Capture parsing uses caller-provided byte storage. Parsed record bytes borrow that
storage rather than allocating implicitly.

---

## AD-016 — Capture processing preserves rejected, ambiguous, and unrecoverable evidence

**Status:** Accepted

### Decision

Whole-file processing does not collapse all non-decoded input into a single
failure state.

Capture audit distinguishes at least:

- `rejected` — the logger line could not be converted into byte data;
- `unrecoverable` — bytes were obtained but no complete valid frame
  interpretation survived;
- `ambiguous` — multiple complete interpretations survived;
- `recovered` — exactly one complete interpretation survived.

A malformed line does not abort processing of later lines.

### Why

These statuses describe materially different evidence. Preserving the distinction
makes later debugging and provenance review possible and prevents coverage metrics
from hiding uncertainty.

---

## AD-017 — Whole-capture orchestration drains each record before reusing byte storage

**Status:** Accepted

### Decision

`CaptureCursor` must completely drain the current recovered record before asking
`EntryIterator` for the next record.

The shared stateful J1587 decoder may survive across records, but borrowed capture
bytes may not.

### Why

`EntryIterator` intentionally reuses caller-provided byte storage. Reusing that
storage before all `FrameView`, parameter, and observation borrows from the
current record are finished would invalidate active protocol data.

At the same time, PID 192 reassembly state is specifically designed to persist
across physical frames and capture records.

### Consequence

The pipeline preserves this distinction:

```text
borrowed record bytes
    → must be drained before reuse

stateful decoder / multisection bank
    → intentionally survives into later records
```

Synthetic tests verify PID 192 completion across separate capture records while
respecting this storage lifetime rule.

---

## AD-018 — Recovered non-J1587 J1708 frames remain visible evidence

**Status:** Accepted

### Decision

A recovered checksum-valid J1708 frame whose MID is outside the J1587 range is not
an error and is not silently discarded.

The capture pipeline exposes it as an `unhandled_frame` event with basic frame
metadata and a reason such as `not_j1587`.

Unsupported J1587 page/layout cases may be surfaced through the same evidence
channel when they are not structurally invalid.

### Why

Valid J1708 traffic is broader than J1587 traffic.

The first full authentic-capture run exposed repeated recovered frames outside
the J1587 MID range. Treating those frames as fatal caused the initial
end-to-end inspection attempt to abort even though the underlying J1708 evidence
was valid.

Preserving them as events keeps protocol support boundaries separate from capture
validity.

---

## AD-019 — Protocol endpoints are capture-local evidence, not permanent device identity

**Status:** Accepted

### Decision

Protocol endpoint identifiers remain scoped to the protocol and capture context in
which they were observed.

Examples include:

- J1587 MID;
- J1939 source address;
- ISO-TP source and destination address bytes.

Numerically equal values across different protocol namespaces are not treated as
proof that they identify the same controller or physical ECU.

### Why

Network addressing is operational and protocol-specific. Addresses may be reused,
changed, assigned dynamically, or interpreted differently by different protocols.

HDZ therefore preserves endpoint observations as evidence and keeps their protocol
namespace explicit.

### Consequence

Higher-level correlation may relate observations from different endpoints when the
capture provides supporting evidence, but the relationship must preserve the reason
for the association rather than silently merging the endpoints into one device
identity.

---

## AD-020 — Cross-protocol correlation preserves the reason for association

**Status:** Accepted

### Decision

When HDZ relates observations across protocol boundaries, the relationship must
state the evidence that justifies the association.

An exact payload match is represented as exact byte equality between observations.
It does not by itself establish that the observations have the same standardized
meaning or originate from the same physical ECU.

### Why

Authentic capture evidence has shown that a J1939 Component Identification payload
can exactly match the bytes following a UDS ReadDataByIdentifier DID.

That is stronger evidence than numeric address coincidence, but it still does not
prove a universal DID meaning or permanent physical-device identity.

### Consequence

Correlation results remain evidence-bearing relationships.

Higher-level diagnostic code may use multiple relationships together to form stronger
inferences, but HDZ does not silently promote one observed relationship into a
controller or physical ECU identity claim.

---

## AD-021 — ISO-TP/UDS remains separate from J1939

**Status:** Accepted

### Decision

ISO-TP session reconstruction and UDS message decoding remain a protocol path
separate from J1939.

The presence of both protocol families in the same CAN capture does not make
ISO-TP traffic part of J1939, even when both use 29-bit CAN identifiers or
contain numerically equal address values.

### Why

J1939 and ISO-TP/UDS have different transport, routing, and message semantics.

Treating ISO-TP as a J1939 subprotocol would blur those boundaries and could
cause capture-local addressing or transport behavior from one protocol to be
given meaning that belongs to the other.

Authentic capture evidence can still reveal relationships between observations
produced by the two protocol paths.

### Consequence

CAN capture data may feed both J1939 and ISO-TP processing where appropriate,
but each protocol layer reports its own facts.

Cross-protocol association belongs in the correlation layer, where the evidence
supporting the relationship can be preserved explicitly.

---

## AD-022 — Durable value relationships reference durable evidence values

**Status:** Accepted

### Decision

Correlation-capable evidence that must survive parser or reassembly lifetimes is
copied into capture-local durable evidence storage.

Distinct durable evidence values receive capture-local evidence-value identifiers.
Relationships refer to those evidence values and preserve the reason for the
association rather than referring directly to protocol endpoints or creating a
controller or physical ECU identity.

Exact repeated evidence may resolve to the same durable evidence value while
retaining an occurrence count. Equal payload bytes observed with different protocol
metadata remain distinct evidence values and may be related explicitly.

### Why

Borrowed observation payloads are not sufficient for relationships that must survive
the parser or transport-reassembly storage that produced them.

Protocol endpoint addresses are also not suitable relationship identities because
they are protocol-specific capture evidence rather than permanent device identity.

Durable evidence values provide stable capture-local references to the exact evidence
that justified a relationship while keeping the original protocol metadata intact.

### Consequence

Value-level relationships can be preserved and queried across the capture lifetime
without merging protocol endpoints or promoting the relationship into a physical
identity claim.

Evidence-value identifiers remain meaningful only within the capture-local evidence
inventory that produced them.

This decision does not establish occurrence-level provenance or temporal
relationships between repeated observations.

---

## AD-023 — Protocol assembly reports derivation; capture orchestration owns lineage

**Status:** Accepted

### Decision

Occurrence-level provenance belongs to the capture and orchestration layers rather
than inside protocol data types.

Protocol parsers and reassemblers remain responsible for protocol facts: whether a
frame was accepted into a transfer, what logical payload bytes it contributed, when
a transfer completed, and when protocol state was aborted or otherwise changed.

They must not own capture-specific identities, timestamps, line numbers, filenames,
adapter identities, or other source metadata merely to preserve provenance.

The capture/orchestration layer combines protocol-reported assembly facts with the
capture occurrence currently being processed. That layer is responsible for
preserving lineage from observed or recovered frame occurrences through logical
messages and later diagnostic observations.

Reassembled-message provenance must be capable of identifying the actual
contributing frame occurrences. A single timestamp or first/last record range is not
sufficient because unrelated traffic may occur between contributors to one logical
message.

Durable evidence-value identity remains separate from occurrence identity. Exact
repeated evidence may continue to collapse into one durable value while individual
occurrences remain independently traceable.

### Why

Making protocol reassemblers retain capture occurrence identifiers would couple
capture policy to otherwise capture-independent protocol machinery.

Tracking transport provenance entirely in parallel would create a second component
that must independently reproduce session membership and reassembly decisions,
creating the possibility that payload reconstruction and provenance reconstruction
disagree.

The chosen boundary keeps protocol assembly authoritative while allowing a
capture-level provenance layer to preserve exact derivation without duplicating
transport logic.

It also preserves HDZ's bounded-storage architecture: protocol semantics do not
depend on how much lineage a particular caller chooses to retain.

### Consequence

HDZ should be able to trace a diagnostic observation back through the logical
message or parameter that produced it and ultimately to the capture occurrences
that contributed to that result.

Protocol types such as J1708 frame views, CAN frame views, J1939 logical-message
views, and ISO-TP completed messages remain capture-independent.

Future occurrence-level relationships such as temporal ordering, request/response,
sequence, and state-transition relationships should reference occurrences rather
than durable evidence values.

This decision establishes the ownership boundary for provenance.

### Implementation checkpoint

The first concrete implementation of this decision is now established.

Capture orchestration uses a capture-local `FrameOccurrenceId` rather than
embedding capture identity in protocol types. Protocol reassembly reports
message-relative payload contributions, and capture-level code can project those
contributions into evidence-relative byte ranges.

`EvidencePayloadContribution` records the frame occurrence and evidence-relative
range supplied by that frame. Bounded correlation-evidence occurrence storage
can then retain multiple occurrences of the same durable evidence value without
duplicating the durable value itself.

Authentic-capture validation has demonstrated this model on both sides of one
cross-protocol relationship:

- five J1939 TP.DT occurrences contribute the complete 33-byte FEEB evidence;
- six ISO-TP occurrences contribute the 33-byte F157 evidence after projection
  past the UDS service and DID bytes;
- RTS, CTS, and ISO-TP Flow Control do not contribute payload bytes; RTS
  establishes transfer start, while CTS and ISO-TP Flow Control provide
  transport context.

The focused developer-inspector implementation is not yet a generalized
capture-ingestion pipeline, and the J1939 proof collector is narrower than the
multi-session protocol assembler.

---

# Open architecture questions

The provenance ownership boundary, capture-local frame-occurrence identity,
payload-contribution representation, and payload-versus-transport-context
distinction are now established.

The remaining questions are narrower:

- how should capture namespaces be represented when evidence may come from
  multiple files, adapters, or future live capture sources;
- how should source-specific timing evidence be preserved without assuming that
  timestamps from different capture sources or clock domains are directly
  comparable;
- how should transport-context occurrences be retained and related to evidence
  occurrences when they do not contribute payload bytes;
- how should the proven occurrence model be generalized from focused
  developer-inspector paths into reusable capture orchestration;
- which occurrence-level relationships should be introduced first: temporal,
  request/response, sequence, or state-transition relationships.

These questions should continue to be resolved through small authentic-capture
proofs before HDZ promotes richer occurrence relationships into durable
diagnostic conclusions.

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
