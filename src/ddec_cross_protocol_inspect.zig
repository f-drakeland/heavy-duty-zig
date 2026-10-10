const std = @import("std");
const Io = std.Io;

const correlation = @import("correlation.zig");
const capture_lineage = @import("capture_lineage.zig");
const j1939_capture_lineage = @import("j1939_capture_lineage.zig");
const isotp_capture_lineage = @import("isotp_capture_lineage.zig");
const evidence_lineage = @import("evidence_lineage.zig");
const ddec_csv = @import("ddec_csv.zig");
const isotp = @import("isotp.zig");
const j1939 = @import("j1939.zig");

// Operational bounds for this whole-file developer CLI.
// These are not protocol limits.
const max_capture_bytes = 64 * 1024 * 1024;

const component_sample_capacity = 16;
// Developer-CLI bound for contributors retained with one component sample.
// This is not a J1939 protocol limit.
const component_lineage_capacity = 16;
const correlation_evidence_capacity = 256;
const relationship_capacity = 256;
const lineage_occurrence_capacity = 4;
const lineage_contribution_capacity = 16;
const session_capacity = 16;
const payload_capacity = 4095;
// One payload contribution must supply at least one logical-message byte.
// Using the payload bound here therefore covers every contributor that can
// participate in one accepted ISO-TP message without assuming full CAN DLC.
const isotp_transport_lineage_capacity = payload_capacity;

const ComponentSampleError = error{
    MissingRawPayload,
    ComponentPayloadTooLarge,
    ComponentSampleCapacityExceeded,
    ComponentLineageCapacityExceeded,
};

const OwnedComponentSample = struct {
    source_address: u8 = 0,
    delivery: j1939.MessageDelivery =
        .single_frame,

    bytes: [j1939.transport.reassembly.maximum_message_size]u8 =
        undefined,

    len: usize = 0,

    lineage_contributions: [component_lineage_capacity]capture_lineage.EvidencePayloadContribution =
        undefined,

    lineage_contribution_count: usize = 0,

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

    fn setLineage(
        self: *OwnedComponentSample,
        contributions: []const capture_lineage.EvidencePayloadContribution,
    ) ComponentSampleError!void {
        if (contributions.len >
            self.lineage_contributions.len)
        {
            return error.ComponentLineageCapacityExceeded;
        }

        @memcpy(
            self.lineage_contributions[0..contributions.len],
            contributions,
        );

        self.lineage_contribution_count =
            contributions.len;
    }

    fn setMessageLineage(
        self: *OwnedComponentSample,
        contributions: []const capture_lineage.MessagePayloadContribution,
    ) ComponentSampleError!void {
        if (contributions.len >
            self.lineage_contributions.len)
        {
            return error.ComponentLineageCapacityExceeded;
        }

        for (contributions, 0..) |contribution, index| {
            self.lineage_contributions[index] = .{
                .frame_occurrence = contribution.frame_occurrence,
                .evidence_offset = contribution.message_offset,
                .byte_length = contribution.byte_length,
            };
        }

        self.lineage_contribution_count =
            contributions.len;
    }

    fn lineage(
        self: *const OwnedComponentSample,
    ) []const capture_lineage.EvidencePayloadContribution {
        return self.lineage_contributions[0..self.lineage_contribution_count];
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

fn appendProjectedEvidenceContribution(
    storage: []capture_lineage.EvidencePayloadContribution,
    count: *usize,
    frame_occurrence: capture_lineage.FrameOccurrenceId,
    message_contribution: correlation.PayloadRange,
    evidence_span: correlation.PayloadRange,
) !void {
    const projected =
        correlation.projectPayloadContribution(
            message_contribution,
            evidence_span,
        ) orelse
        return;

    if (count.* >= storage.len) {
        return error.LineageContributionCapacityExceeded;
    }

    storage[count.*] = .{
        .frame_occurrence = frame_occurrence,
        .evidence_offset = projected.offset,
        .byte_length = projected.byte_length,
    };

    count.* += 1;
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

    var next_frame_occurrence_index: usize = 0;

    const LineageTracker =
        j1939_capture_lineage.J1939TransportLineageTracker(
            4,
            component_lineage_capacity,
        );

    var lineage_tracker: LineageTracker = .{};

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

        const frame_occurrence: capture_lineage.FrameOccurrenceId = .{
            .index = next_frame_occurrence_index,
        };

        next_frame_occurrence_index += 1;

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

        var direct_component_contribution: ?capture_lineage.EvidencePayloadContribution = null;
        var completed_transport_lineage: ?LineageTracker.CompletedLineage = null;

        const assembly_result =
            assembler.pushFrameWithDerivation(
                frame,
            ) catch
                continue;

        switch (assembly_result.derivation) {
            .transport_started => |transfer| {
                try lineage_tracker.start(
                    transfer,
                );
            },

            .transport_payload => |derivation| {
                try lineage_tracker.recordPayload(
                    frame_occurrence,
                    derivation,
                );

                if (assembly_result.event) |assembly_event| {
                    switch (assembly_event) {
                        .message => {
                            completed_transport_lineage =
                                try lineage_tracker.finish(
                                    derivation.transfer,
                                );
                        },

                        else => {},
                    }
                }
            },

            .direct_message => |contribution| {
                if (frame.identifier().pgn ==
                    j1939.pgn_component_identification)
                {
                    direct_component_contribution = .{
                        .frame_occurrence = frame_occurrence,
                        .evidence_offset = contribution.offset,
                        .byte_length = contribution.byte_length,
                    };
                }
            },

            .none,
            .transport_context,
            => {},
        }

        const assembly_event =
            assembly_result.event orelse
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

                                    var sample =
                                        try OwnedComponentSample.fromObservation(
                                            component,
                                        );

                                    if (direct_component_contribution) |contribution| {
                                        const direct =
                                            [_]capture_lineage.EvidencePayloadContribution{
                                                contribution,
                                            };

                                        try sample.setLineage(
                                            &direct,
                                        );
                                    } else if (completed_transport_lineage) |lineage| {
                                        try sample.setMessageLineage(
                                            lineage.slice(),
                                        );
                                    }

                                    samples[sample_count.*] =
                                        sample;

                                    sample_count.* += 1;
                                },

                                else => {},
                            }
                        },
                    }
                }
            },

            .transport_aborted => |aborted| {
                if (aborted.transfer) |transfer| {
                    try lineage_tracker.abort(
                        transfer,
                    );
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

    const EvidenceOccurrences =
        evidence_lineage.CorrelationEvidenceOccurrenceInventory(
            lineage_occurrence_capacity,
            lineage_contribution_capacity,
        );

    var evidence_inventory: EvidenceInventory = .{};
    var relationships: Relationships = .{};
    var evidence_occurrences: EvidenceOccurrences = .{};
    var j1939_occurrence_recorded: [component_sample_capacity]bool =
        @splat(false);

    var next_frame_occurrence_index: usize = 0;

    const LineageTracker =
        isotp_capture_lineage.IsotpTransportLineageTracker(
            session_capacity,
            isotp_transport_lineage_capacity,
        );

    var lineage_tracker: LineageTracker = .{};

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

        const frame_occurrence: capture_lineage.FrameOccurrenceId = .{
            .index = next_frame_occurrence_index,
        };

        next_frame_occurrence_index += 1;

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

        const push_result =
            router.pushWithDerivation(
                source_address,
                destination_address,
                frame,
            ) catch
                continue;

        const event =
            push_result.event;

        var completed_transport_lineage: ?LineageTracker.CompletedLineage =
            null;

        switch (push_result.derivation) {
            .transport_started => |derivation| {
                try lineage_tracker.start(
                    frame_occurrence,
                    derivation,
                );

                switch (event) {
                    .completed => {
                        completed_transport_lineage =
                            try lineage_tracker.finish(
                                derivation.transfer,
                            );
                    },

                    else => {},
                }
            },

            .transport_payload => |derivation| {
                try lineage_tracker.recordPayload(
                    frame_occurrence,
                    derivation,
                );

                switch (event) {
                    .completed => {
                        completed_transport_lineage =
                            try lineage_tracker.finish(
                                derivation.transfer,
                            );
                    },

                    else => {},
                }
            },

            .none,
            .direct_message,
            .transport_context,
            => {},
        }

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
                var f157_occurrence_recorded = false;

                var f157_contributions: [lineage_contribution_capacity]capture_lineage.EvidencePayloadContribution =
                    undefined;

                var f157_contribution_count: usize = 0;

                const traces_f157 =
                    message.source_address == 0x00 and
                    message.destination_address == 0xf1 and
                    message.delivery == .multi_frame and
                    uds_evidence.data_identifier == 0xf157;

                if (traces_f157) {
                    const lineage =
                        completed_transport_lineage orelse
                        return error.F157TransportLineageMissing;

                    const evidence_span: correlation.PayloadRange = .{
                        .offset = 3,
                        .byte_length = uds_evidence.data_after_identifier.len,
                    };

                    for (lineage.slice()) |contribution| {
                        try appendProjectedEvidenceContribution(
                            &f157_contributions,
                            &f157_contribution_count,
                            contribution.frame_occurrence,
                            .{
                                .offset = contribution.message_offset,
                                .byte_length = contribution.byte_length,
                            },
                            evidence_span,
                        );
                    }
                }

                for (
                    samples[0..sample_count],
                    0..,
                ) |*sample, sample_index| {
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

                    if (!j1939_occurrence_recorded[
                        sample_index
                    ]) {
                        const lineage =
                            sample.lineage();

                        if (lineage.len == 0) {
                            return error.J1939ComponentLineageMissing;
                        }

                        const occurrence_id =
                            try evidence_occurrences.record(
                                j1939_result.id,
                                lineage,
                            );

                        const occurrence =
                            evidence_occurrences
                                .occurrence(
                                occurrence_id,
                            ) orelse
                            return error.RecordedOccurrenceMissing;

                        std.debug.print(
                            "lineage: J1939 FEEB occurrence #{} -> evidence #{} contributors={}\n",
                            .{
                                occurrence.id.index,
                                occurrence.value_id.index,
                                occurrence.contributions.len,
                            },
                        );

                        for (
                            occurrence.contributions,
                        ) |contribution| {
                            std.debug.print(
                                "  frame occurrence #{} -> evidence offset={} length={}\n",
                                .{
                                    contribution.frame_occurrence.index,
                                    contribution.evidence_offset,
                                    contribution.byte_length,
                                },
                            );
                        }

                        j1939_occurrence_recorded[
                            sample_index
                        ] = true;
                    }

                    const uds_owned =
                        try CorrelationEvidence
                            .fromUdsDataIdentifier(
                            uds_evidence,
                        );

                    const uds_result =
                        try evidence_inventory.observe(
                            uds_owned,
                        );

                    if (traces_f157 and
                        !f157_occurrence_recorded)
                    {
                        const occurrence_id =
                            try evidence_occurrences.record(
                                uds_result.id,
                                f157_contributions[0..f157_contribution_count],
                            );

                        const occurrence =
                            evidence_occurrences
                                .occurrence(
                                occurrence_id,
                            ) orelse
                            return error.RecordedOccurrenceMissing;

                        std.debug.print(
                            "lineage: UDS F157 occurrence #{} -> evidence #{} contributors={}\n",
                            .{
                                occurrence.id.index,
                                occurrence.value_id.index,
                                occurrence.contributions.len,
                            },
                        );

                        for (
                            occurrence.contributions,
                        ) |contribution| {
                            std.debug.print(
                                "  frame occurrence #{} -> evidence offset={} length={}\n",
                                .{
                                    contribution.frame_occurrence.index,
                                    contribution.evidence_offset,
                                    contribution.byte_length,
                                },
                            );
                        }

                        f157_occurrence_recorded = true;
                    }

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
