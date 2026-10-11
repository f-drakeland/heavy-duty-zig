# Heavy Duty Zig — Authentic Cross-Protocol Lineage Validation

Updated: 2026-10-10

This document records an authentic-capture validation of HDZ's cross-protocol
evidence and occurrence-lineage architecture.

The capture itself remains private and is not distributed with the repository.

## What was validated

HDZ independently reconstructed two protocol observations carrying the same
33-byte evidence payload:

- J1939 PGN 65259 / FEEB Component Identification, delivered through RTS/CTS;
- UDS ReadDataByIdentifier response DID F157, delivered through ISO-TP.

The resulting durable evidence values were related by
`exact_payload_equality`.

No claim is made that protocol equality alone proves a physical ECU identity.

## J1939 evidence lineage

The 33-byte FEEB evidence was reconstructed from five TP.DT frame occurrences:

```text
frame #24125 -> evidence [ 0.. 7)
frame #24144 -> evidence [ 7..14)
frame #24162 -> evidence [14..21)
frame #24180 -> evidence [21..28)
frame #24199 -> evidence [28..33)

```

RTS and CTS frames remain transport context and are not represented as payload
contributors.

## UDS evidence lineage

The logical UDS response contains the service byte and DID before the F157
evidence payload. HDZ projects ISO-TP message contributions into the evidence
subrange rather than treating message offsets as evidence offsets.

The resulting 33-byte evidence lineage is:

```text
frame #82347 -> evidence [ 0.. 3)
frame #82351 -> evidence [ 3..10)
frame #82353 -> evidence [10..17)
frame #82367 -> evidence [17..24)
frame #82369 -> evidence [24..31)
frame #82371 -> evidence [31..33)
```

The ISO-TP Flow Control frame remains transport context and is not a payload
contributor.

## Durable relationship

The authentic run produced:

```text
J1939 correlation-evidence occurrence #0
    -> evidence value #0

UDS correlation-evidence occurrence #1
    -> evidence value #1

evidence #0
    exact_payload_equality, 33 bytes
evidence #1
```

This demonstrates that HDZ can preserve the distinction between:

```text
capture frame occurrence
    -> evidence occurrence
    -> durable evidence value
    -> reason-bearing relationship
```

## Current limits

This document records a focused authentic-capture validation run, but the
transport-lineage machinery demonstrated by that run is no longer specific to
the developer inspector.

HDZ now exposes reusable bounded `can_diagnostic_pipeline` orchestration for
J1939 and the observed 29-bit ISO-TP address-byte form. Protocol reassembly
remains authoritative for transfer membership and message-relative payload
derivation, while the orchestration layer attaches capture-occurrence identity
and returns completed payload lineage.

The reusable pipeline preserves the two protocol interpretations independently.
Malformed or capacity-limited traffic on one path can be reported without
discarding a valid outcome from the other, and focused state-recovery tests
verify that rejected overlap and session exhaustion do not contaminate an
already-active transfer or its lineage.

Diagnostic evidence selection is still performed by the focused
cross-protocol inspector. That inspector also projects ISO-TP logical-message
lineage past the UDS service and DID bytes into the evidence-relative range and
records the durable `exact_payload_equality` relationship.

HDZ therefore has reusable CAN transport-to-lineage orchestration, but does not
claim one universal capture-to-diagnostic-output application pipeline spanning
all input formats and protocol families.

The validation also does not establish that the matching J1939 and UDS evidence
came from the same physical ECU. The retained relationship states only what the
capture proves: exact equality of the two preserved evidence payloads.
