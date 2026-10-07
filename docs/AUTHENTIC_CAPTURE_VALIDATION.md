# Heavy Duty Zig — Authentic Capture Validation

Updated: 2026-10-07

This document records an end-to-end validation of Heavy Duty Zig (HDZ) against
an authentic J1708/J1587 logger capture.

The purpose is to preserve empirical evidence for Milestone 5 without copying
third-party capture bytes into this repository.

## Scope

This validation exercises the current file-backed ingestion path:

```text
authentic logger text
        ↓
capture_text
        ↓
capture record bytes
        ↓
conservative frame recovery
        ↓
J1708 FrameView(s)
        ↓
J1587 ParameterIterator
        ↓
FrameCursor / stateful Decoder
        ↓
typed observations and unsupported evidence
```

This is a capture-file validation. It does not claim live bus acquisition,
waveform decoding, or recovery of physical idle timing that was not preserved by
the logger.

---

## External corpus

Repository:

```text
romdnop/j1708
```

Validated file:

```text
logs/вн0645ох_freightliner_white.txt
```

The corpus was kept external to the HDZ repository.

No redistribution permission or license for the capture material was established
during this work, so HDZ does not copy or bundle capture bytes from this file.
Permanent HDZ tests use synthetic fixtures instead.

---

## Validation command

The current inspection tool was built with:

```bash
zig17 build-exe src/capture_inspect.zig
```

The authentic file was then processed with:

```bash
./capture_inspect "../../j1708-corpus/logs/вн0645ох_freightliner_white.txt"   > /tmp/hdz-inspect.txt
```

The resulting summary was:

```text
Capture summary
records:       308
recovered:     294
ambiguous:     14
unrecoverable: 0
rejected:      0
events:        1128
```

### Recovery rate

Of 308 logger records:

- 294 had exactly one surviving complete J1708 frame interpretation;
- 14 had multiple surviving complete interpretations;
- 0 had no valid complete interpretation;
- 0 failed text capture parsing.

That is approximately:

- 95.5% uniquely recovered;
- 4.5% ambiguous;
- 0% unrecoverable;
- 0% rejected.

The ambiguous records were intentionally not forced into one guessed boundary
interpretation.

---

## Typed J1587 observations

The authentic capture produced nine typed observations through the full HDZ
pipeline:

```text
6 vehicle_distance
2 diagnostic_code
1 component_identification
```

The observation-bearing logger records were:

```text
line 25:  component_identification

line 28:  vehicle_distance
line 110: vehicle_distance
line 170: vehicle_distance
line 229: vehicle_distance
line 238: vehicle_distance
line 290: vehicle_distance

line 290: diagnostic_code
line 308: diagnostic_code
```

This demonstrates that authentic logger text can currently reach typed protocol
observations without using synthetic pseudo-message input.

### Decoded observation contents

The inspection tool was then extended to print the decoded contents of supported
observations while leaving the underlying protocol representation unchanged.

The authentic component-identification observation on line 25 decoded as:

```text
source MID:    128
component MID: 128
manufacturer:  "CMMNS"
model:         "99 N14-475E"
serial:        "<redacted-serial>"
```

These strings are recorded as decoded protocol fields only. This validation does
not independently identify the physical component or expand `"CMMNS"` into a
manufacturer name.

The six vehicle-distance observations were identical:

```text
source MID: 128
raw count:  14485030
kilometers: 2332089.83
miles:      1448503.00
```

The same raw count and decoded distance appeared on lines 28, 110, 170, 229, 238,
and 290.

The two diagnostic-code observations decoded as:

```text
line 290:
    source MID:       128
    identifier kind:  pid
    identifier:       190
    FMI:              2
    status:           inactive
    occurrence count: 1

line 308:
    source MID:       140
    identifier kind:  pid
    identifier:       168
    FMI:              1
    status:           active
    occurrence count: not present
```

The inspection CLI trims presentation padding such as trailing spaces and NUL
bytes from component-identification fields for display only. The parser-level
decoded slices remain unchanged.

This output strengthens the end-to-end result: HDZ is not only recognizing
observation types from the authentic file, but surfacing concrete decoded
diagnostic evidence from them.

---

## Unsupported J1587 parameters

The capture also produced a large amount of valid but currently unsupported
J1587 parameter evidence.

The most common unsupported PIDs were:

```text
139 × PID 84
139 × PID 91
139 × PID 92
139 × PID 190

 68 × PID 85
 68 × PID 121
 68 × PID 183
 68 × PID 184

 45 × PID 128
 27 × PID 168

 15 × PID 83
 15 × PID 89
 15 × PID 100
 15 × PID 102

 14 × PID 65
 14 × PID 70
 14 × PID 71
 14 × PID 108
 14 × PID 110

 13 × PID 105
 13 × PID 175

  7 × PID 86
  7 × PID 87

  2 × PID 0
  1 × PID 74
```

These parameters were not treated as malformed merely because HDZ does not yet
decode their semantics.

This validates the design rule that unsupported protocol evidence remains visible
to callers.

---

## Non-J1587 J1708 traffic

The recovered event stream contained checksum-valid J1708 frames whose MIDs were
outside the J1587 range:

```text
21 × MID 5
21 × MID 7
```

These frames were surfaced as `not_j1587` evidence rather than aborting the
capture or being mislabeled as bad data.

HDZ currently does not assign higher-level meaning to these frames.

Their repeated, symmetric appearance is useful evidence that valid J1708 traffic
outside the J1587 message range can occur in the capture and must remain distinct
from J1587 parsing failures.

---

## Ambiguous records

The 14 ambiguous logger records were:

```text
27
29
74
79
90
91
135
136
178
179
214
241
254
292
```

These 14 records reduce to eight distinct byte patterns because several records
repeat the same logger payload.

Repeated patterns include:

- the pattern on line 90 also appearing on lines 135, 178, 214, and 292;
- the pattern on line 91 also appearing on lines 136 and 179.

### Why ambiguity is expected

J1708 physical message boundaries are established by bus idle timing.

The validated text logger does not preserve that physical timing. Once multiple
physical J1708 messages are concatenated into one logger record, checksum
arithmetic alone may be insufficient to reconstruct the original boundaries.

A concatenation of checksum-valid J1708 frames is itself checksum-valid.

Therefore one logger byte sequence may have both:

```text
[ valid frame ][ valid frame ]
```

and:

```text
[       one valid frame       ]
```

as complete checksum-valid interpretations.

When both interpretations also survive the structural evidence available to HDZ,
the original physical boundary cannot be proven from the retained bytes alone.

### Example behavior

One recurring ambiguous pattern in the capture has two complete surviving
interpretations:

```text
interpretation A:
    [ frame ][ frame ]

interpretation B:
    [       one frame       ]
```

Both satisfy the available J1708 checksum evidence and known J1587 structural
rules.

HDZ therefore reports the logger record as `ambiguous` rather than selecting one
interpretation based on unsupported assumptions.

Some of the other ambiguous records admit more than two complete surviving
interpretations.

### Validation conclusion for ambiguity

The 14 ambiguous records are not currently considered recovery failures.

They demonstrate the intended conservative behavior:

> When the original physical boundary cannot be proven from retained capture
> evidence, HDZ reports ambiguity instead of inventing certainty.

---

## Multisection state across capture records

Separate synthetic tests verify that PID 192 reassembly state survives across
different J1708 frames and across different capture records when the same
stateful decoder is retained.

This is important because the text adapter reuses caller-provided byte storage
between records.

The pipeline therefore drains the current record completely before reading the
next logger record, while retaining only the decoder state that is explicitly
designed to survive between frames.

The authentic validation above passed through that same orchestration path.

---

## Evidence-preservation behavior validated

This capture run exercised several distinctions intentionally built into HDZ:

```text
logger parse failure
    ≠
unrecoverable J1708 bytes

unrecoverable
    ≠
ambiguous

ambiguous
    ≠
invalid

valid J1708
    ≠
must be J1587

valid J1587 parameter
    ≠
HDZ currently supports its semantics

PID 192 pending state
    ≠
caller-visible completed observation
```

The authentic corpus exposed all of these layers without requiring HDZ to
collapse them into a single success/failure result.

---

## Current limitations

This validation does not establish:

- original physical J1708 frame boundaries for ambiguous logger records;
- legality of longer J1708 messages under the vehicle's original operating state;
- semantics for every observed MID or PID;
- correctness of capture timestamps or logger metadata;
- live RP1210, serial, J2534, or other hardware acquisition;
- waveform-level J1708 or J2497/PLC decoding;
- complete heavy-duty diagnostic coverage.

The validated claim is narrower:

> HDZ can ingest this authentic text capture, conservatively recover the J1708
> evidence that can be proven from the retained bytes, preserve unresolved
> evidence, parse J1587 parameters, maintain multisection decoder state, and
> produce typed diagnostic observations.

---

## Milestone significance

This run is the first end-to-end authentic-data validation of the Milestone 5
pipeline.

Before this point, individual protocol and orchestration layers were covered by
synthetic unit tests and selected local authentic-data checks.

This full-file run demonstrates that those layers compose over 308 authentic
logger records without requiring the project to weaken its ambiguity rules or
treat unsupported traffic as invalid.

Future protocol coverage work should preserve these recovery and evidence
semantics rather than increasing apparent decode coverage by guessing.
