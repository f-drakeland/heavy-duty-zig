const std = @import("std");
const Io = std.Io;

const correlation = @import("correlation.zig");
const ddec_csv = @import("ddec_csv.zig");
const isotp = @import("isotp.zig");
const j1939 = @import("j1939.zig");

// Operational bounds for this whole-file developer CLI.
// These are not protocol limits.
const max_capture_bytes =
    64 * 1024 * 1024;

const component_sample_capacity = 16;
const correlation_evidence_capacity = 256;
const relationship_capacity = 256;
const session_capacity = 16;
const payload_capacity = 4095;

const ComponentSampleError = error{
    MissingRawPayload,
    ComponentPayloadTooLarge,
    ComponentSampleCapacityExceeded,
};

const OwnedComponentSample = struct {
    source_address: u8 = 0,
    delivery: j1939.MessageDelivery =
        .single_frame,

    bytes: [j1939.transport.reassembly.maximum_message_size]u8 =
        undefined,

    len: usize = 0,

    fn fromObservation(
        component: j1939.ComponentIdentificationObservation,
    ) ComponentSampleError!OwnedComponentSample {
        const raw_payload =
            component.raw_payload orelse
            return error.MissingRawPayload;

        if (raw_payload.len >
            j1939.transport.reassembly.maximum_message_size)
        {
            return error.ComponentPayloadTooLarge;
        }

        var result: OwnedComponentSample = .{
            .source_address = component.source_address,
            .delivery = component.delivery,
        };

        @memcpy(
            result.bytes[0..raw_payload.len],
            raw_payload,
        );

        result.len = raw_payload.len;

        return result;
    }

    fn payload(
        self: *const OwnedComponentSample,
    ) []const u8 {
        return self.bytes[0..self.len];
    }

    fn observation(
        self: *const OwnedComponentSample,
    ) j1939.component_identification.ParseError!j1939.ComponentIdentificationObservation {
        const raw_payload =
            self.payload();

        const component =
            try j1939.component_identification.parse(
                raw_payload,
            );

        return .{
            .source_address = self.source_address,
            .delivery = self.delivery,
            .make = component.make,
            .model = component.model,
            .serial_number = component.serial_number,
            .unit_number = component.unit_number,
            .raw_payload = raw_payload,
        };
    }
};

fn isObserved18DaIdentifier(
    identifier: u32,
) bool {
    return (identifier & 0x1fff0000) ==
        0x18da0000;
}

fn sourceAddress(
    identifier: u32,
) u8 {
    return @truncate(identifier);
}

fn destinationAddress(
    identifier: u32,
) u8 {
    return @truncate(identifier >> 8);
}

fn collectJ1939ComponentSamples(
    text: []const u8,
    samples: *[component_sample_capacity]OwnedComponentSample,
    sample_count: *usize,
) !void {
    var assembler =
        j1939.MessageAssembler(
            j1939.transport.reassembly.maximum_message_size,
            4,
        ){};

    var lines =
        std.mem.splitScalar(
            u8,
            text,
            '\n',
        );

    while (lines.next()) |line| {
        const trimmed =
            std.mem.trim(
                u8,
                line,
                " \t\r",
            );

        if (trimmed.len == 0) {
            continue;
        }

        const parsed =
            ddec_csv.parseLine(
                trimmed,
            ) catch
                continue;

        const record = switch (parsed) {
            .non_can => continue,
            .can => |record| record,
        };

        if (record.identifier_format != .extended) {
            continue;
        }

        const can_frame =
            record.frame() catch
                continue;

        const frame =
            j1939.FrameView.fromCanFrame(
                can_frame,
            ) catch
                continue;

        const maybe_assembly_event =
            assembler.pushFrame(
                frame,
            ) catch
                continue;

        const assembly_event =
            maybe_assembly_event orelse
            continue;

        switch (assembly_event) {
            .message => |message| {
                var cursor =
                    j1939.MessageCursor.init(
                        message,
                    ) catch
                        continue;

                while (true) {
                    const maybe_event =
                        cursor.next() catch
                            break;

                    const event =
                        maybe_event orelse
                        break;

                    switch (event) {
                        .unsupported_pgn => {},

                        .observation => |observation| {
                            switch (observation) {
                                .component_identification => |component| {
                                    if (sample_count.* >=
                                        samples.len)
                                    {
                                        return error.ComponentSampleCapacityExceeded;
                                    }

                                    samples[sample_count.*] =
                                        try OwnedComponentSample.fromObservation(
                                            component,
                                        );

                                    sample_count.* += 1;
                                },

                                else => {},
                            }
                        },
                    }
                }
            },

            else => {},
        }
    }
}

fn inspectUdsMatches(
    text: []const u8,
    samples: *const [component_sample_capacity]OwnedComponentSample,
    sample_count: usize,
) !void {
    var router =
        isotp.SessionRouter(
            session_capacity,
            payload_capacity,
        ){};

    var uds_did_responses: usize = 0;
    var uds_evidence_rejected: usize = 0;
    var exact_matches: usize = 0;

    const CorrelationEvidence =
        correlation.OwnedCorrelationEvidence(payload_capacity);

    const EvidenceInventory =
        correlation.CorrelationEvidenceInventory(
            correlation_evidence_capacity,
            payload_capacity,
        );

    const Relationships =
        correlation.EvidenceRelationshipInventory(relationship_capacity);

    var evidence_inventory: EvidenceInventory = .{};
    var relationships: Relationships = .{};

    var lines =
        std.mem.splitScalar(
            u8,
            text,
            '\n',
        );

    while (lines.next()) |line| {
        const trimmed =
            std.mem.trim(
                u8,
                line,
                " \t\r",
            );

        if (trimmed.len == 0) {
            continue;
        }

        const parsed =
            ddec_csv.parseLine(
                trimmed,
            ) catch
                continue;

        const record = switch (parsed) {
            .non_can => continue,
            .can => |record| record,
        };

        if (record.identifier_format != .extended) {
            continue;
        }

        const can_frame =
            record.frame() catch
                continue;

        const identifier =
            can_frame.identifier();

        if (!isObserved18DaIdentifier(
            identifier,
        )) {
            continue;
        }

        const source_address =
            sourceAddress(identifier);

        const destination_address =
            destinationAddress(identifier);

        const frame =
            isotp.parse(
                can_frame.data(),
            ) catch
                continue;

        if (frame == .unsupported) {
            continue;
        }

        const event =
            router.push(
                source_address,
                destination_address,
                frame,
            ) catch
                continue;

        switch (event) {
            .in_progress => {},

            .flow_control => {},

            .completed => |message| {
                const maybe_evidence =
                    correlation
                        .fromUdsReadDataByIdentifierResponse(
                        message,
                    ) catch {
                        uds_evidence_rejected += 1;
                        continue;
                    };

                const uds_evidence =
                    maybe_evidence orelse
                    continue;

                uds_did_responses += 1;

                for (
                    samples[0..sample_count],
                ) |*sample| {
                    const component =
                        sample.observation() catch
                            continue;

                    const match =
                        correlation
                            .matchJ1939ComponentPayloadToUdsDataIdentifier(
                            component,
                            uds_evidence,
                        ) orelse
                        continue;

                    const j1939_owned =
                        (try CorrelationEvidence
                            .fromJ1939ComponentIdentification(
                            component,
                        )) orelse
                        continue;

                    const j1939_result =
                        try evidence_inventory.observe(
                            j1939_owned,
                        );

                    const uds_owned =
                        try CorrelationEvidence
                            .fromUdsDataIdentifier(
                            uds_evidence,
                        );

                    const uds_result =
                        try evidence_inventory.observe(
                            uds_owned,
                        );

                    const durable_relationship =
                        evidence_inventory
                            .exactPayloadRelationship(
                            j1939_result.id,
                            uds_result.id,
                        ) orelse
                        return error.DurableRelationshipMismatch;

                    _ = try relationships.record(
                        durable_relationship,
                    );

                    exact_matches += 1;

                    std.debug.print(
                        "match: J1939 SA {X:0>2} {s} <-> UDS {X:0>2}->{X:0>2} DID 0x{X:0>4} {s}: {} bytes\n",
                        .{
                            match.j1939_source_address,
                            @tagName(
                                match.j1939_delivery,
                            ),
                            match.uds_source_address,
                            match.uds_destination_address,
                            match.data_identifier,
                            @tagName(
                                match.uds_delivery,
                            ),
                            match.byte_length,
                        },
                    );
                }
            },
        }
    }

    std.debug.print(
        \\
        \\J1939 component payloads preserved: {}
        \\UDS DID responses examined: {}
        \\UDS DID evidence rejected: {}
        \\exact cross-protocol payload matches: {}
        \\durable exact-payload relationships preserved: {}
        \\
    ,
        .{
            sample_count,
            uds_did_responses,
            uds_evidence_rejected,
            exact_matches,
            relationships.count(),
        },
    );

    if (relationships.count() != 0) {
        std.debug.print(
            "\ncapture-level evidence relationships:\n",
            .{},
        );
    }

    var relationship_index: usize = 0;

    while (relationships.relationshipAt(
        relationship_index,
    )) |stored_relationship| : (relationship_index += 1) {
        const relationship =
            stored_relationship.relationship.*;

        std.debug.print(
            "  relationship #{} reason={s} byte_length={}\n",
            .{
                relationship_index,
                @tagName(relationship.reason),
                relationship.byte_length,
            },
        );

        const left =
            evidence_inventory.evidence(
                relationship.left,
            ) orelse {
                std.debug.print(
                    "    left evidence could not be resolved\n",
                    .{},
                );
                continue;
            };

        const right =
            evidence_inventory.evidence(
                relationship.right,
            ) orelse {
                std.debug.print(
                    "    right evidence could not be resolved\n",
                    .{},
                );
                continue;
            };

        const Sides = [_]struct {
            label: []const u8,
            view: EvidenceInventory.EvidenceView,
        }{
            .{
                .label = "left",
                .view = left,
            },
            .{
                .label = "right",
                .view = right,
            },
        };

        for (Sides) |side| {
            switch (side.view.evidence.*) {
                .j1939_component_identification_payload => |value| {
                    std.debug.print(
                        "    {s} evidence #{} occurrences={}: J1939 SA {X:0>2} {s} component-identification payload\n",
                        .{
                            side.label,
                            side.view.id.index,
                            side.view.occurrence_count,
                            value.source_address,
                            @tagName(value.delivery),
                        },
                    );
                },

                .uds_data_identifier_response => |value| {
                    std.debug.print(
                        "    {s} evidence #{} occurrences={}: UDS {X:0>2}->{X:0>2} DID 0x{X:0>4} {s} response data\n",
                        .{
                            side.label,
                            side.view.id.index,
                            side.view.occurrence_count,
                            value.source_address,
                            value.destination_address,
                            value.data_identifier,
                            @tagName(value.delivery),
                        },
                    );
                },
            }
        }
    }
}

pub fn main(
    init: std.process.Init,
) !void {
    const io = init.io;
    const arena =
        init.arena.allocator();

    const args =
        try init.minimal.args.toSlice(
            arena,
        );

    if (args.len != 2) {
        std.debug.print(
            "usage: ddec_cross_protocol_inspect <capture-file>\n",
            .{},
        );
        return;
    }

    const text =
        try Io.Dir.cwd().readFileAlloc(
            io,
            args[1],
            arena,
            .limited(max_capture_bytes),
        );

    var component_samples: [component_sample_capacity]OwnedComponentSample =
        undefined;

    var component_sample_count: usize = 0;

    try collectJ1939ComponentSamples(
        text,
        &component_samples,
        &component_sample_count,
    );

    try inspectUdsMatches(
        text,
        &component_samples,
        component_sample_count,
    );
}
