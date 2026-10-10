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

This is an authentic-capture developer-inspector proof of the architecture, not
yet a generalized capture-ingestion pipeline.

The J1939 component-lineage collector used by this proof is narrower than the
multi-session protocol assembler and should not be treated as general
concurrent-transfer lineage handling.

The validation also does not establish that the matching J1939 and UDS evidence
came from the same physical ECU. The retained relationship states only what the
capture proves: exact equality of the two preserved evidence payloads.
