# Heavy Duty Zig

Open truck-side diagnostic infrastructure for Zig.

Heavy Duty Zig is a standalone library for observing, decoding, and
interpreting heavy-duty commercial vehicle network data.

## Current scope

Heavy Duty Zig currently supports diagnostic evidence extraction from
J1708/J1587, J1939, and observed ISO-TP/UDS traffic.

### J1708/J1587

- checksum-stripped variable-length J1587 message parsing
- PID 192 multisection reassembly
- PID 234 software identification
- PID 237 VIN
- PID 243 component identification
- PID 245 total vehicle distance
- PID 194 diagnostic code table decoding
- active/inactive fault status
- PID/SID identification
- FMI decoding
- occurrence count handling
- page-two identifier expansion
- stateful J1587 message decoding
- automatic PID 192 multisection handling
- typed observation delivery from raw J1587 messages
- explicit handling of unsupported valid parameters

### J1939

- 29-bit J1939 identifier parsing and PGN classification
- single-frame logical message handling
- BAM transport reassembly
- passive reconstruction of directed RTS-initiated transport
- transport session separation by source and destination
- transport abort observation and session cleanup
- DM1 lamp and diagnostic trouble code decoding
- EEC1 engine-speed observations
- Address Claimed PGN decoding
- raw J1939 NAME preservation and typed NAME fields
- Component Identification PGN decoding
- typed observation delivery from reconstructed J1939 messages
- explicit preservation of unsupported PGNs and transport controls

### ISO-TP/UDS

- ISO-TP single-frame and multi-frame message reconstruction
- bounded session routing by observed source and destination address bytes
- flow-control observation and active-transfer matching
- UDS service-message and negative-response parsing
- ReadDataByIdentifier response structure and DID evidence
- exact cross-protocol payload correlation without assuming shared physical identity

## Design

Protocol layers report protocol facts.

Higher-level diagnostic code is responsible for assigning meaning to those
facts.

Network addresses, protocol identities, component-identification fields, and
other observations remain evidence. Heavy Duty Zig does not assume that a
source address alone permanently identifies a physical ECU.

Heavy Duty Zig is intentionally separate from Trailer Fingerprint Software.
TFS may eventually consume this library, but Heavy Duty Zig does not contain
trailer fingerprinting logic.

## Status

Early development.

Current input begins after physical-layer decoding. J1708 input currently
expects checksum handling to have already occurred, and J1939 input begins
with decoded CAN frames or supported capture records.

Heavy Duty Zig can currently turn supported J1708/J1587 and J1939 traffic into
typed diagnostic observations. J1939 logical messages may arrive directly,
through BAM reassembly, or through passive reconstruction of directed
RTS-initiated transport.

Directed J1939 transport support is currently passive and evidence-oriented.
Heavy Duty Zig can reconstruct observed payloads and track transport aborts,
but it does not implement an active RTS/CTS endpoint or claim successful
transport completion merely because all payload bytes were observed.

Passive cross-observation correlation is now implemented for capture-local
endpoint and identity evidence, including exact cross-protocol payload
relationships. These relationships remain evidence and are not promoted to
permanent controller or physical ECU identity. Active diagnostic requests,
fault clearing, programming operations, and physical-layer acquisition are
not implemented yet.

## Tracking

Current diagnostic direction:

1. Correlate observations without prematurely treating network addresses as
   permanent ECU identity.
2. Build a passive network/controller inventory from observed evidence such as
   source address, J1939 NAME, component identification, diagnostic messages,
   telemetry, and transport relationships.
3. Add further PGN or parameter decoding when authentic capture evidence shows
   that it materially improves diagnosis or controller identification.
4. Preserve unsupported and ambiguous evidence instead of silently assigning
   higher-level meaning.

The current architectural problem is preserving and querying relationships
between observations without prematurely promoting those relationships to
controller or physical ECU identity. Correlation must retain why evidence was
associated, such as exact payload equality, while preserving the distinction
between network address, controller-application identity, component identity,
and physical ECU identity.
