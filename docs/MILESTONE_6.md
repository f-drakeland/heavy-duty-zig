# Heavy Duty Zig — Milestone 6

## Goal

Establish a passive CAN/J1939 diagnostic pipeline alongside the existing
J1708/J1587 pipeline.

Milestone 6 should prove that HDZ can support a modern heavy-duty network
without redesigning or weakening the evidence-first architecture established
during Milestone 5.

## Architectural direction

```text
J1708 / J1587                         CAN / J1939
      │                                    │
      ▼                                    ▼
capture / recovery                   capture / framing
      │                                    │
      ▼                                    ▼
J1587 parameters                     J1939 messages
      │                                    │
      ▼                                    ▼
typed observations                   typed observations
      │                                    │
      └───────────────┬────────────────────┘
                      ▼
              diagnostic evidence
```

The two protocol families remain independent until they have produced
protocol-specific facts.

HDZ must not invent a generic vehicle-frame abstraction that erases meaningful
differences between J1708 and CAN/J1939.

## Initial scope

Milestone 6 includes:

- passive CAN capture ingestion;
- a CAN frame representation appropriate for J1939 traffic;
- J1939 29-bit identifier parsing;
- source address, priority, PGN, and destination semantics where applicable;
- preservation of unsupported J1939 traffic as evidence;
- a small, diagnostically useful set of typed J1939 observations;
- DM1 diagnostic trouble-code support;
- receive-side J1939 transport reassembly where required by authentic traffic;
- end-to-end validation against authentic J1939 capture data.

## Non-goals

Milestone 6 does not require:

- live RP1210 or other hardware acquisition;
- active diagnostic requests;
- fault clearing;
- ECU programming;
- complete PGN/SPN coverage;
- J1708/J1587 removal or replacement;
- cross-protocol diagnostic correlation;
- J1939-22 / CAN FD support unless authentic evidence makes it necessary.

## Evidence rule

The Milestone 5 rule remains in force:

> Protocol layers report facts. Higher layers assign diagnostic meaning.

Unsupported, ambiguous, incomplete, or unknown J1939 evidence must remain
distinguishable from malformed traffic.

Decode coverage must not be increased by guessing.

## Current progress

The passive CAN/J1939 pipeline is now established through authentic capture
validation.

Current demonstrated capabilities include:

- candump-style passive CAN capture ingestion;
- classical CAN frame validation;
- J1939 29-bit identifier and PGN decoding;
- concurrent BAM receive-side transport reassembly;
- logical J1939 message construction;
- preservation of unsupported PGNs as evidence;
- DM1 lamp decoding and DTC parsing support;
- EEC1 SPN 190 engine-speed decoding as a typed operating-state observation.

Against the current private authentic Class 6 truck capture, HDZ processed
34,980 CAN/J1939 frames with:

- 34,980 records parsed;
- 0 parse rejections;
- 0 J1939 rejections;
- 42 completed BAM transfers;
- 151 DM1 lamp observations;
- 2,644 EEC1 engine-speed observations;
- 0 assembly errors;
- 0 decode errors.

The authentic capture contains no populated DM1 trouble-code observations, so
authentic populated-DTC validation remains outstanding.

## Completion criteria

Milestone 6 is complete when HDZ can take an authentic passive CAN/J1939
capture and, through the normal library pipeline:

1. preserve the original CAN framing evidence;
2. decode J1939 identifier semantics;
3. preserve unsupported traffic without treating it as invalid;
4. reassemble supported multi-packet traffic when required;
5. produce typed operating-state and diagnostic observations;
6. decode authentic DM1 fault evidence;
7. document the empirical results and remaining limitations;
8. pass the package test suite without weakening the evidence rules established
   during Milestone 5.
