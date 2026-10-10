# Heavy Duty Zig — Milestone 7

## Status

**Redirected before completion as originally specified.**

Milestone 7 established important parts of the intended J1939 identity path,
including Address Claim / NAME evidence, Component Identification evidence,
capture-local endpoint handling, and durable identity evidence. It did not
complete every item in the original scope below.

In particular, the J1939 Software Identification and Vehicle Identification
decoders described by this plan were not completed, and HDZ did not adopt the
J1939-specific `ControllerApplication` inventory shape sketched here. Instead,
authentic capture evidence redirected the project toward protocol-neutral
capture-local endpoint inventories, ISO-TP/UDS observation, cross-protocol
correlation, durable evidence values, reason-bearing relationships, and
diagnostic evidence inventories.

The original milestone plan is retained below as historical design context
rather than rewritten to make the completed implementation appear to match it.
Unfinished decoding items are not automatically current roadmap obligations;
additional PGN, PID, or DID support remains driven by demonstrated diagnostic
value in authentic evidence.

## Goal

Establish a passive, manufacturer-neutral J1939 controller identity and network
inventory layer.

Milestone 7 should allow HDZ to turn standardized J1939 identity traffic into
typed identity evidence while preserving the distinction between:

- a source address;
- a J1939 controller application NAME;
- descriptive component identity;
- software identity;
- vehicle identity;
- and any later inference about a physical ECU or component.

The milestone must not make core identity handling dependent on a particular
engine, ECU, vehicle, or manufacturer.

## Architectural direction

HDZ already produces trustworthy operating-state and diagnostic observations
from both legacy and modern heavy-duty protocol paths.

Milestone 7 extends the modern J1939 path with identity evidence:

    J1939 traffic
          │
          ├── operating-state observations
          │
          ├── diagnostic observations
          │
          └── identity observations
                    │
                    ├── Address Claim / NAME
                    ├── Component Identification
                    ├── Software Identification
                    └── Vehicle Identification
                              │
                              ▼
                       network inventory

Identity remains evidence.

The network inventory may associate observations that the capture itself
supports, but it must not silently promote an observed relationship into a
stronger physical-device claim.

## Identity model

Milestone 7 must preserve several concepts separately.

### Source address

A J1939 source address is an observed network address.

It is not permanent ECU identity.

HDZ must not assume that a particular source address always represents a
particular ECU role, component, or manufacturer.

For example, core code must not contain assumptions equivalent to:

    source 0x00 means a particular manufacturer's engine controller

A source address may be associated with identity evidence only because that
relationship was observed in the network traffic.

### J1939 NAME

The 64-bit J1939 NAME carried by Address Claim traffic identifies a J1939
controller application.

NAME is stronger identity evidence than a source address, but Milestone 7 must
not automatically equate one NAME with one physical ECU enclosure.

A physical device may expose more than one controller application, and the
capture may not contain enough evidence to prove their physical relationship.

The inventory should therefore be capable of representing:

    controller application / NAME
              │
              └── currently observed source address

without requiring:

    one NAME == one physical ECU

Repeated observation of the same NAME/address relationship must not create
duplicate controller records.

### Descriptive identity

Standardized identity PGNs provide descriptive facts associated with an
observed J1939 source.

Milestone 7 initially includes:

- PGN 60928 / 0x00EE00 — Address Claimed;
- PGN 65259 / 0x00FEEB — Component Identification;
- PGN 65242 / 0x00FEDA — Software Identification;
- PGN 65260 / 0x00FEEC — Vehicle Identification.

These observations must remain attributable to their observed source and
delivery method.

### Physical-component identity

Milestone 7 does not require HDZ to prove that multiple controller
applications, source addresses, or identity messages belong to the same
physical ECU.

Such correlation may be attempted by a later diagnostic layer only when the
available evidence supports it.

## Manufacturer-neutral rule

Core J1939 identity decoding must model standardized protocol evidence, not
manufacturer-specific behavior.

Manufacturer information is data.

It must not select the core parser architecture.

Standard identity handling must work without requiring knowledge that a
component was produced by Cummins, Detroit, Allison, Bendix, PACCAR, or any
other manufacturer.

Manufacturer-specific or proprietary decoding, if added later, must remain
behind an explicit extension boundary and must not change the meaning of
standard J1939 identity types.

## Evidence-preservation rules

The evidence-first rules established by earlier milestones remain in force.

> Protocol layers report facts. Higher layers assign diagnostic meaning.

Milestone 7 additionally requires:

- source address must not be treated as permanent identity;
- priority must not be treated as identity;
- repeated identical evidence must be handled idempotently;
- empty standardized fields must remain representable as empty fields;
- unknown or unexplained trailing payload data must not be silently discarded;
- conflicting identity observations must remain visible;
- incomplete identity evidence must remain distinguishable from malformed
  identity traffic;
- unsupported identity traffic must remain observable evidence;
- manufacturer codes and manufacturer strings must remain data rather than
  parser-selection mechanisms.

## Authentic evidence

The existing authentic Class 6 truck capture contains identity traffic from
multiple source addresses and multiple apparent component roles.

Observed Address Claim traffic includes four claims across three source
addresses:

- source 0x00 — one claim;
- source 0x03 — two identical claims;
- source 0x29 — one claim.

The repeated source 0x03 claim provides authentic evidence for idempotent
inventory updates.

The capture also contains 17 BAM-transported standardized identity messages:

- 8 Component Identification messages;
- 7 Software Identification messages;
- 2 Vehicle Identification messages.

Component Identification is observed from:

- source 0x00;
- source 0x03;
- source 0x0B;
- source 0x31.

Software Identification is observed from:

- source 0x00;
- source 0x03;
- source 0x05;
- source 0x0B.

Vehicle Identification is observed from:

- source 0x00.

The same standardized identity PGNs are observed at different J1939
priorities. Priority therefore remains message metadata and must not become
part of ECU identity.

### Authentic Component Identification shapes

Authentic FEEB payloads include examples equivalent to:

    PACCR*CECU3-NAMUX2* * *
    ALLSN*2100-2200 RDS***
    BNDWS*EC60-sta*<redacted-serial>**
    CMMNS*<redacted-component>*<redacted-serial>*...

The corpus therefore exercises:

- multiple make identifiers;
- multiple apparent ECU/component roles;
- populated fields;
- empty fields;
- space-filled fields;
- variable message lengths;
- and additional delimiter/trailing data.

The parser must not be designed around one manufacturer's field contents.

### Authentic Software Identification shapes

Authentic FEDA messages contain different declared software-field counts,
different field lengths, empty fields, and space-filled fields.

Examples include messages with declared counts of two, four, and six software
identification fields.

Empty fields are evidence and must not disappear merely because a generic
string-splitting helper would normally filter them.

### Authentic Vehicle Identification

The authentic FEEC message carries the vehicle identifier:

    <redacted-vin>

The capture contains the same vehicle-identification observation more than
once, providing another idempotency case for the inventory layer.

## Initial scope

Milestone 7 includes:

- passive Address Claim parsing;
- 64-bit J1939 NAME representation and field access;
- typed Address Claim observations;
- Component Identification payload parsing;
- Software Identification payload parsing;
- Vehicle Identification payload parsing;
- typed identity observations;
- attribution of identity observations to observed J1939 source addresses;
- preservation of BAM delivery provenance;
- a passive network inventory capable of retaining controller-application and
  descriptive identity evidence;
- idempotent handling of repeated observations;
- explicit handling of incomplete or conflicting identity evidence;
- end-to-end validation against the existing authentic identity-bearing
  capture.

## Non-goals

Milestone 7 does not require:

- manufacturer-specific proprietary PGN decoding;
- manufacturer-specific ECU classes;
- assumptions about fixed source-address ownership;
- active J1939 identity requests;
- ECU programming;
- fault clearing;
- live RP1210 or other hardware acquisition;
- a complete SAE J1939 identity catalog;
- physical-ECU correlation when the capture does not prove it;
- J1708/J1587-to-J1939 component matching;
- cross-protocol diagnostic correlation;
- a permanent external database of manufacturers or ECU models.

Cross-protocol identity and diagnostic correlation remain candidates for a
later milestone after each protocol family can independently produce
trustworthy identity evidence.

## Inventory behavior

The initial network inventory should be conservative.

A useful conceptual model is:

    NetworkInventory
          │
          ├── ControllerApplication
          │      NAME
          │      observed source address
          │      NAME-derived standardized fields
          │
          └── IdentityEvidence
                 source address
                 component identification
                 software identification
                 vehicle identification
                 delivery provenance

The exact implementation does not have to match this structure, but it must
preserve these distinctions.

The inventory must not silently transform:

    two observations from the same source address

into:

    proof of one permanent physical ECU

nor transform:

    similar NAME subfields

into:

    proof that two controller applications occupy the same physical device

unless a later layer has evidence sufficient to support that conclusion.

## Completion criteria

Milestone 7 is complete when HDZ can take authentic passive J1939 traffic and,
through the normal library pipeline:

1. decode Address Claim messages and preserve the full 64-bit NAME;
2. expose standardized NAME fields without manufacturer-specific assumptions;
3. distinguish controller-application identity from current source address;
4. decode authentic Component Identification messages;
5. decode authentic Software Identification messages while preserving empty
   fields and declared field-count semantics;
6. decode authentic Vehicle Identification messages;
7. emit typed identity observations with source and delivery provenance;
8. construct a passive network inventory from those observations;
9. handle repeated identical evidence idempotently;
10. preserve incomplete, conflicting, unsupported, or unexplained identity
    evidence rather than silently normalizing it away;
11. validate the identity path against multiple authentic source addresses and
    more than one apparent ECU/component role;
12. pass the package test suite without weakening the evidence-first rules
    established by earlier milestones.

## Architectural constraint for future work

Milestone 7 should leave HDZ in a position where later cross-protocol
correlation can ask:

    Does this J1939 controller/component identity evidence
    refer to the same physical component as this J1587 identity evidence?

Milestone 7 itself must not answer that question prematurely.

The purpose of this milestone is to make the evidence on the J1939 side strong
enough that a later correlation layer can answer it honestly.
