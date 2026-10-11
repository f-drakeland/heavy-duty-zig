# Heavy Duty Zig

Evidence-preserving truck-side diagnostic infrastructure for Zig.

Heavy Duty Zig is a standalone library for observing, decoding, and
reasoning about heavy-duty commercial vehicle network data. It preserves
protocol facts, diagnostic evidence, uncertainty, and evidence-backed
relationships without silently promoting network observations into stronger
physical-device claims.

## See the evidence model in 30 seconds

With Zig 0.17:

```sh
zig build demo
```

The included synthetic capture carries the same 33-byte evidence payload through
two independent protocol paths: J1939 Component Identification over directed
RTS/CTS and UDS ReadDataByIdentifier over multi-frame ISO-TP.

HDZ reconstructs both observations, preserves the exact frame occurrences that
contributed payload bytes on each path, and records their payload equality as
evidence.

It does **not** turn that equality into a claim that both observations came from
the same physical ECU.

`zig build check` runs the full repository verification, including this public
demo against its expected output.

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

## Using Heavy Duty Zig

Heavy Duty Zig exposes the Zig module `heavy_duty`.

For a local checkout, add HDZ to the consuming project's `build.zig.zon`:

```zig
.dependencies = .{
    .heavy_duty_zig = .{
        .path = "../heavy-duty-zig",
    },
},
```

Resolve the dependency in `build.zig`:

```zig
const heavy_duty_dependency =
    b.dependency("heavy_duty_zig", .{
        .target = target,
        .optimize = optimize,
    });

const heavy_duty =
    heavy_duty_dependency.module("heavy_duty");
```

Then make the module available to the consuming root module:

```zig
.imports = &.{
    .{
        .name = "heavy_duty",
        .module = heavy_duty,
    },
},
```

Application code can then import the library with:

```zig
const heavy_duty = @import("heavy_duty");
```

For CAN-side diagnostic orchestration, HDZ also exposes a bounded single-pass
pipeline that keeps J1939 and the observed ISO-TP path independent while
preserving capture-occurrence lineage.

Given an already-decoded `can.FrameView`:

```zig
const DiagnosticPipeline =
    heavy_duty.can_diagnostic_pipeline.Pipeline(
        4,   // J1939 transport sessions
        4,   // ISO-TP sessions
        256, // ISO-TP payload bytes
    );

var pipeline: DiagnosticPipeline = .{};

const result =
    pipeline.push(
        .{ .index = occurrence_index },
        frame,
    );

switch (result.j1939) {
    .none => {},
    .event => |event| {
        _ = event;
    },
    .failure => |err| {
        _ = err;
    },
}

switch (result.isotp) {
    .none => {},
    .event => |event| {
        _ = event;
    },
    .failure => |err| {
        _ = err;
    },
}
```

Reassembled message payloads and lineage borrow pipeline-owned storage and
should be consumed before the next call to `push`.

This dependency path has been validated from a separate Zig 0.17 consumer
project.

## Verification

With Zig 0.17, run the canonical repository verification command:

```sh
zig build check
```

This checks repository formatting, runs the library test suite, and verifies
the public cross-protocol lineage demo against its expected output.

To run the public demonstration interactively instead:

```sh
zig build demo
```

## Public cross-protocol lineage demo

A small synthetic capture is included at
`captures/public/cross_protocol_lineage_demo.csv`.

The fixture contains no authentic vehicle identity data. It carries the
synthetic 33-byte Component Identification payload:

```text
HDZ*PUBLIC-DEMO*SYNTH0001*UNIT01*
```

The same payload is transported independently as:

- J1939 PGN 65259 / FEEB Component Identification through directed RTS/CTS;
- UDS ReadDataByIdentifier DID F157 through multi-frame ISO-TP.

Run the public proof with:

```sh
zig build demo
```

The result preserves separate occurrence lineage on both protocol paths and
then records an `exact_payload_equality` relationship between the two durable
evidence values.

The J1939 evidence comes from five TP.DT frame occurrences. RTS and CTS remain
transport context and are not payload contributors.

The UDS evidence comes from the ISO-TP First Frame plus five Consecutive
Frames. The Flow Control frame remains transport context and is not a payload
contributor.

The demo intentionally proves evidence equality only. It does not claim that
the two observations identify the same physical ECU.

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

Significant design decisions and their rationale are recorded in
[Architecture Decisions](docs/ARCHITECTURE_DECISIONS.md).

## Status

Heavy Duty Zig is pre-1.0 and under active development. Public APIs may still
change.

Current input begins after physical-layer decoding. J1708 input begins with
externally delimited checksum-bearing frames or supported capture records; HDZ
validates J1708 checksums and can conservatively recover frame boundaries from
supported capture text. J1939 input begins with decoded CAN frames or supported
capture records.

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

Occurrence-level evidence lineage has been validated against authentic J1939
and ISO-TP/UDS capture data. Both sides of a 33-byte cross-protocol evidence
relationship can be traced independently to the exact frame occurrences that
supplied their payload bytes. See
[Authentic Cross-Protocol Lineage Validation](docs/AUTHENTIC_CROSS_PROTOCOL_LINEAGE_VALIDATION.md).

The CAN-side transport and lineage path is now available through reusable,
bounded `can_diagnostic_pipeline` orchestration rather than existing only in a
focused proof. J1939 and observed ISO-TP remain independent interpretations of
the same CAN frame, and each reports its own event or failure outcome.

The focused cross-protocol inspector still owns diagnostic evidence selection,
UDS evidence-range projection, and relationship construction. HDZ therefore
does not claim one universal capture-to-diagnostic application pipeline across
every supported input family.

## Current direction

Current diagnostic direction:

1. Preserve occurrence-level provenance through capture parsing and transport
   reassembly so logical observations can remain tied to the capture evidence
   that produced them.
2. Keep protocol endpoints, durable evidence values, and evidence-backed
   relationships distinct from permanent controller or physical ECU identity.
3. Add further PGN, PID, or DID decoding when authentic capture evidence shows
   that it materially improves diagnosis, identity, or correlation.
4. Preserve unsupported, ambiguous, incomplete, and conflicting evidence
   instead of silently assigning higher-level meaning.

Occurrence-level provenance is now established at the architectural level.
Protocol reassembly reports derivation facts without owning capture metadata,
while capture orchestration can preserve the exact frame occurrences that
contributed bytes to durable evidence.

This has been validated against authentic J1939 and ISO-TP/UDS traffic: both
sides of an exact 33-byte cross-protocol payload relationship retain their own
capture-frame lineage while transport-control frames remain separate from
payload contributors.

Reusable CAN orchestration now carries the proven occurrence-lineage model
through J1939 and the observed ISO-TP path while keeping protocol assembly
authoritative for transfer membership. J1708/J1587 capture recovery and
decoding remain a separate ingestion path with their own input semantics.

Future work can build on occurrence identity for richer temporal,
request/response, sequence, and state-transition relationships, and can define
how multiple capture sources or clock domains should be represented, without
promoting those relationships into unsupported physical-device claims.

## License

Heavy Duty Zig is available under the [MIT License](LICENSE).
