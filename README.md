# Heavy Duty Zig

Open truck-side diagnostic infrastructure for Zig.

Heavy Duty Zig is a standalone library for observing, decoding, and
interpreting heavy-duty commercial vehicle network data.

## Current scope

Initial support focuses on J1708/J1587:

- checksum-stripped variable-length J1587 message parsing
- PID 192 multisection reassembly
- PID 234 software identification
- PID 237 VIN
- PID 243 component identification
- PID 245 total vehicle distance
- PID 194 diagnostic code table decoding
- active/inactive fault status
- PID/SID identifcation
- FMI decoding
- occurrence count handling
- page-two identfier expansion

## Design

Protocol layers report protocol facts.

Higher-level diagnostic code is responsible for assigning meaning to those
facts.

Heavy Duty Zig is intentionally separate from Trailer Fingerprint Software.
TFS may eventually consume this library, but Heavy Duty Zig does not contain
trailer fingerprinting logic.

## Status

Early development.

Current input begins after physical-layer decoding and checksum handling.

Passive J1587 diagnostic observation is supported. The library can decode
structured PID 194 fault records, including multisection diagnostic tables.

Live J1708/J1939 transport, diagnostic correlation, active diagnostic
requests, fault clearing, and programming operations are not implemented yet.