const std = @import("std");
const Io = std.Io;

const correlation = @import("correlation.zig");
const can_diagnostic_pipeline = @import("can_diagnostic_pipeline.zig");
const capture_lineage = @import("capture_lineage.zig");
const evidence_lineage = @import("evidence_lineage.zig");
const ddec_csv = @import("ddec_csv.zig");
const j1939 = @import("j1939.zig");

// Operational bounds for this whole-file developer CLI.
// These are not protocol limits.
const max_capture_bytes = 64 * 1024 * 1024;
const correlation_evidence_capacity = 256;
const relationship_capacity = 256;
const lineage_occurrence_capacity = 256;
const lineage_contribution_capacity = 4096;
const session_capacity = 16;
const payload_capacity = 4095;
// One payload contribution must supply at least one logical-message byte.
// Using the payload bound here therefore covers every contributor that can
// participate in one accepted ISO-TP message without assuming full CAN DLC.
const isotp_transport_lineage_capacity = payload_capacity;
const j1939_transport_lineage_capacity = 255;

fn isRecoverablePipelineError(
    err: anyerror,
) bool {
    return switch (err) {
        error.InvalidBamDestination,
        error.InvalidDirectedTransportDestination,
        error.InvalidLength,
        error.InvalidSequenceNumber,
        error.InvalidMessageSize,
        error.PacketCountMismatch,
        error.TransferAlreadyActive,
        error.NoActiveTransfer,
        error.SourceAddressMismatch,
        error.UnexpectedSequenceNumber,
        error.InvalidPacketDataLength,
        error.EmptyFrame,
        error.UnsupportedSingleFrameEscapeLength,
        error.UnsupportedFirstFrameExtendedLength,
        error.InvalidSingleFrameLength,
        error.TruncatedSingleFrame,
        error.TruncatedFirstFrame,
        error.InvalidFirstFrameLength,
        error.TruncatedConsecutiveFrame,
        error.TruncatedFlowControl,
        error.UnsupportedFrameType,
        => true,

        else => false,
    };
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

fn inspectSinglePass(
    text: []const u8,
) !void {
    const CanPipeline =
        can_diagnostic_pipeline.Pipeline(
            session_capacity,
            session_capacity,
            payload_capacity,
        );

    const CorrelationEvidence =
        correlation.OwnedCorrelationEvidence(
            payload_capacity,
        );

    const EvidenceInventory =
        correlation.CorrelationEvidenceInventory(
            correlation_evidence_capacity,
            payload_capacity,
        );

    const Relationships =
        correlation.EvidenceRelationshipInventory(
            relationship_capacity,
        );

    const EvidenceOccurrences =
        evidence_lineage.CorrelationEvidenceOccurrenceInventory(
            lineage_occurrence_capacity,
            lineage_contribution_capacity,
        );

    var pipeline: CanPipeline = .{};
    var evidence_inventory: EvidenceInventory = .{};
    var relationships: Relationships = .{};
    var evidence_occurrences: EvidenceOccurrences = .{};

    var j1939_component_payloads: usize = 0;
    var uds_did_responses: usize = 0;
    var uds_evidence_rejected: usize = 0;
    var exact_matches: usize = 0;

    var next_frame_occurrence_index: usize = 0;

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

        const frame_occurrence: capture_lineage.FrameOccurrenceId =
            .{
                .index = next_frame_occurrence_index,
            };

        next_frame_occurrence_index += 1;

        const can_frame =
            record.frame() catch
                continue;

        const result =
            pipeline.push(
                frame_occurrence,
                can_frame,
            );

        var fatal_pipeline_error: ?anyerror = null;

        switch (result.j1939) {
            .none => {},

            .failure => |err| {
                if (!isRecoverablePipelineError(err)) {
                    fatal_pipeline_error = err;
                }
            },

            .event => |pipeline_event| {
                switch (pipeline_event) {
                    .message => |completed| {
                        const maybe_cursor: ?j1939.MessageCursor =
                            j1939.MessageCursor.init(
                                completed.message,
                            ) catch null;

                        if (maybe_cursor) |initial_cursor| {
                            var cursor =
                                initial_cursor;

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
                                                const owned =
                                                    (try CorrelationEvidence
                                                        .fromJ1939ComponentIdentification(
                                                        component,
                                                    )) orelse
                                                    continue;

                                                const observed =
                                                    try evidence_inventory.observe(
                                                        owned,
                                                    );

                                                if (completed.lineage.len >
                                                    j1939_transport_lineage_capacity)
                                                {
                                                    return error.LineageContributionCapacityExceeded;
                                                }

                                                var contributions: [j1939_transport_lineage_capacity]capture_lineage.EvidencePayloadContribution =
                                                    undefined;

                                                for (
                                                    completed.lineage,
                                                    0..,
                                                ) |contribution, index| {
                                                    contributions[index] = .{
                                                        .frame_occurrence = contribution.frame_occurrence,
                                                        .evidence_offset = contribution.message_offset,
                                                        .byte_length = contribution.byte_length,
                                                    };
                                                }

                                                const occurrence_id =
                                                    try evidence_occurrences.record(
                                                        observed.id,
                                                        contributions[0..completed.lineage.len],
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

                                                j1939_component_payloads += 1;
                                            },

                                            else => {},
                                        }
                                    },
                                }
                            }
                        }
                    },

                    .transport_aborted,
                    .bam_started,
                    .unsupported_transport_control,
                    => {},
                }
            },
        }

        switch (result.isotp) {
            .none => {},

            .failure => |err| {
                if (!isRecoverablePipelineError(err) and
                    fatal_pipeline_error == null)
                {
                    fatal_pipeline_error = err;
                }
            },

            .event => |pipeline_event| {
                switch (pipeline_event) {
                    .message => |completed| {
                        const maybe_evidence =
                            correlation
                                .fromUdsReadDataByIdentifierResponse(
                                completed.message,
                            ) catch uds_parse: {
                                uds_evidence_rejected += 1;
                                break :uds_parse null;
                            };

                        if (maybe_evidence) |uds_evidence| {
                            uds_did_responses += 1;

                            const owned =
                                try CorrelationEvidence
                                    .fromUdsDataIdentifier(
                                    uds_evidence,
                                );

                            const observed =
                                try evidence_inventory.observe(
                                    owned,
                                );

                            var contributions: [isotp_transport_lineage_capacity]capture_lineage.EvidencePayloadContribution =
                                undefined;

                            var contribution_count: usize = 0;

                            const evidence_span: correlation.PayloadRange =
                                .{
                                    .offset = 3,
                                    .byte_length = uds_evidence
                                        .data_after_identifier
                                        .len,
                                };

                            for (
                                completed.lineage,
                            ) |contribution| {
                                try appendProjectedEvidenceContribution(
                                    &contributions,
                                    &contribution_count,
                                    contribution.frame_occurrence,
                                    .{
                                        .offset = contribution.message_offset,
                                        .byte_length = contribution.byte_length,
                                    },
                                    evidence_span,
                                );
                            }

                            if (contribution_count != 0) {
                                const occurrence_id =
                                    try evidence_occurrences.record(
                                        observed.id,
                                        contributions[0..contribution_count],
                                    );

                                const occurrence =
                                    evidence_occurrences
                                        .occurrence(
                                        occurrence_id,
                                    ) orelse
                                    return error.RecordedOccurrenceMissing;

                                if (uds_evidence.data_identifier ==
                                    0xf157)
                                {
                                    std.debug.print(
                                        "lineage: UDS F157 occurrence #{} -> evidence #{} contributors={}\n",
                                        .{
                                            occurrence.id.index,
                                            occurrence.value_id.index,
                                            occurrence.contributions.len,
                                        },
                                    );
                                } else {
                                    std.debug.print(
                                        "lineage: UDS DID 0x{X:0>4} occurrence #{} -> evidence #{} contributors={}\n",
                                        .{
                                            uds_evidence.data_identifier,
                                            occurrence.id.index,
                                            occurrence.value_id.index,
                                            occurrence.contributions.len,
                                        },
                                    );
                                }

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
                            }
                        }
                    },

                    .flow_control,
                    .unsupported_frame,
                    => {},
                }
            },
        }

        if (fatal_pipeline_error) |err| {
            return err;
        }
    }

    var first_index: usize = 0;

    while (first_index <
        evidence_inventory.count()) : (first_index += 1)
    {
        const first_id: correlation.EvidenceValueId =
            .{ .index = first_index };

        const first =
            evidence_inventory.evidence(
                first_id,
            ) orelse
            continue;

        var second_index =
            first_index + 1;

        while (second_index <
            evidence_inventory.count()) : (second_index += 1)
        {
            const second_id: correlation.EvidenceValueId =
                .{ .index = second_index };

            const second =
                evidence_inventory.evidence(
                    second_id,
                ) orelse
                continue;

            const relationship =
                evidence_inventory
                    .exactPayloadRelationship(
                    first_id,
                    second_id,
                ) orelse
                continue;

            _ = try relationships.record(
                relationship,
            );

            exact_matches +=
                first.occurrence_count *
                second.occurrence_count;

            const left =
                evidence_inventory.evidence(
                    relationship.left,
                ) orelse
                return error.RelationshipEvidenceMissing;

            const right =
                evidence_inventory.evidence(
                    relationship.right,
                ) orelse
                return error.RelationshipEvidenceMissing;

            switch (left.evidence.*) {
                .j1939_component_identification_payload => |j1939_value| {
                    switch (right.evidence.*) {
                        .uds_data_identifier_response => |uds_value| {
                            std.debug.print(
                                "match: J1939 SA {X:0>2} {s} <-> UDS {X:0>2}->{X:0>2} DID 0x{X:0>4} {s}: {} bytes\n",
                                .{
                                    j1939_value.source_address,
                                    @tagName(
                                        j1939_value.delivery,
                                    ),
                                    uds_value.source_address,
                                    uds_value.destination_address,
                                    uds_value.data_identifier,
                                    @tagName(
                                        uds_value.delivery,
                                    ),
                                    relationship.byte_length,
                                },
                            );
                        },

                        else => unreachable,
                    }
                },

                else => unreachable,
            }
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
            j1939_component_payloads,
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
                @tagName(
                    relationship.reason,
                ),
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
                            @tagName(
                                value.delivery,
                            ),
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
                            @tagName(
                                value.delivery,
                            ),
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

    try inspectSinglePass(text);
}
