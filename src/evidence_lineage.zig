const std = @import("std");
const correlation = @import("correlation.zig");
const capture_lineage = @import("capture_lineage.zig");

/// Projects all logical-message frame contributions into a selected
/// diagnostic evidence range.
///
/// The caller owns output storage. The returned slice borrows that storage.
/// Contributions outside the evidence range are excluded. This operation
/// preserves existing projection semantics; it does not independently
/// establish full coverage of the selected evidence range.
pub const ProjectionError = error{
    LineageContributionCapacityExceeded,
};

pub fn projectMessageContributions(
    message_lineage: []const capture_lineage.MessagePayloadContribution,
    evidence_span: correlation.PayloadRange,
    output: []capture_lineage.EvidencePayloadContribution,
) ProjectionError![]const capture_lineage.EvidencePayloadContribution {
    var needed: usize = 0;

    for (message_lineage) |contribution| {
        if (correlation.projectPayloadContribution(
            .{
                .offset = contribution.message_offset,
                .byte_length = contribution.byte_length,
            },
            evidence_span,
        ) != null) {
            needed += 1;
        }
    }

    if (needed > output.len) {
        return error.LineageContributionCapacityExceeded;
    }

    var count: usize = 0;

    for (message_lineage) |contribution| {
        const projected = correlation.projectPayloadContribution(
            .{
                .offset = contribution.message_offset,
                .byte_length = contribution.byte_length,
            },
            evidence_span,
        ) orelse continue;

        output[count] = .{
            .frame_occurrence = contribution.frame_occurrence,
            .evidence_offset = projected.offset,
            .byte_length = projected.byte_length,
        };

        count += 1;
    }

    return output[0..count];
}

test "projects multiframe message lineage into UDS evidence bytes" {
    const input = [_]capture_lineage.MessagePayloadContribution{
        .{ .frame_occurrence = .{ .index = 100 }, .message_offset = 0, .byte_length = 6 },
        .{ .frame_occurrence = .{ .index = 101 }, .message_offset = 6, .byte_length = 7 },
        .{ .frame_occurrence = .{ .index = 102 }, .message_offset = 13, .byte_length = 7 },
        .{ .frame_occurrence = .{ .index = 103 }, .message_offset = 20, .byte_length = 7 },
        .{ .frame_occurrence = .{ .index = 104 }, .message_offset = 27, .byte_length = 7 },
        .{ .frame_occurrence = .{ .index = 105 }, .message_offset = 34, .byte_length = 2 },
    };

    var output: [6]capture_lineage.EvidencePayloadContribution = undefined;

    const projected = try projectMessageContributions(
        &input,
        .{ .offset = 3, .byte_length = 33 },
        &output,
    );

    try std.testing.expectEqual(@as(usize, 6), projected.len);
    try std.testing.expectEqual(@as(usize, 100), projected[0].frame_occurrence.index);
    try std.testing.expectEqual(@as(usize, 0), projected[0].evidence_offset);
    try std.testing.expectEqual(@as(usize, 3), projected[0].byte_length);
    try std.testing.expectEqual(@as(usize, 105), projected[5].frame_occurrence.index);
    try std.testing.expectEqual(@as(usize, 31), projected[5].evidence_offset);
    try std.testing.expectEqual(@as(usize, 2), projected[5].byte_length);

    var insufficient: [5]capture_lineage.EvidencePayloadContribution = undefined;

    try std.testing.expectError(
        error.LineageContributionCapacityExceeded,
        projectMessageContributions(
            &input,
            .{ .offset = 3, .byte_length = 33 },
            &insufficient,
        ),
    );
}

/// Capture-local identity of one correlation-evidence occurrence.
///
/// Multiple occurrences may reference the same durable EvidenceValueId.
pub const CorrelationEvidenceOccurrenceId = struct {
    index: usize,

    pub fn eql(
        self: CorrelationEvidenceOccurrenceId,
        other: CorrelationEvidenceOccurrenceId,
    ) bool {
        return self.index == other.index;
    }
};

pub const CorrelationEvidenceOccurrenceError = error{
    CorrelationEvidenceOccurrenceCapacityExceeded,
    EvidencePayloadContributionCapacityExceeded,
    CorrelationEvidenceOccurrenceRequiresContribution,
};

/// Bounded capture-local storage for individual correlation-evidence
/// occurrences.
///
/// Durable evidence values remain deduplicated in CorrelationEvidenceInventory.
/// Each value_id must come from the CorrelationEvidenceInventory paired with
/// this occurrence inventory by capture orchestration.
/// This inventory preserves each observation separately and associates it with
/// the exact frame occurrences that supplied its evidence bytes.
pub fn CorrelationEvidenceOccurrenceInventory(
    comptime occurrence_capacity: usize,
    comptime contribution_capacity: usize,
) type {
    if (occurrence_capacity == 0) {
        @compileError(
            "evidence occurrence capacity must be greater than zero",
        );
    }

    if (contribution_capacity == 0) {
        @compileError(
            "evidence contribution capacity must be greater than zero",
        );
    }

    return struct {
        const Self = @This();

        const Occurrence = struct {
            value_id: correlation.EvidenceValueId,
            contribution_start: usize,
            contribution_count: usize,
        };

        pub const OccurrenceView = struct {
            id: CorrelationEvidenceOccurrenceId,
            value_id: correlation.EvidenceValueId,
            contributions: []const capture_lineage.EvidencePayloadContribution,
        };

        occurrences: [occurrence_capacity]Occurrence = undefined,
        occurrence_count: usize = 0,

        contributions: [contribution_capacity]capture_lineage.EvidencePayloadContribution =
            undefined,
        contribution_count: usize = 0,

        pub fn record(
            self: *Self,
            value_id: correlation.EvidenceValueId,
            new_contributions: []const capture_lineage.EvidencePayloadContribution,
        ) CorrelationEvidenceOccurrenceError!CorrelationEvidenceOccurrenceId {
            if (new_contributions.len == 0) {
                return error.CorrelationEvidenceOccurrenceRequiresContribution;
            }

            if (self.occurrence_count >= occurrence_capacity) {
                return error.CorrelationEvidenceOccurrenceCapacityExceeded;
            }

            if (new_contributions.len >
                contribution_capacity - self.contribution_count)
            {
                return error.EvidencePayloadContributionCapacityExceeded;
            }

            const id: CorrelationEvidenceOccurrenceId = .{
                .index = self.occurrence_count,
            };

            const contribution_start =
                self.contribution_count;

            @memcpy(
                self.contributions[contribution_start .. contribution_start + new_contributions.len],
                new_contributions,
            );

            self.contribution_count +=
                new_contributions.len;

            self.occurrences[self.occurrence_count] = .{
                .value_id = value_id,
                .contribution_start = contribution_start,
                .contribution_count = new_contributions.len,
            };

            self.occurrence_count += 1;

            return id;
        }

        pub fn count(
            self: *const Self,
        ) usize {
            return self.occurrence_count;
        }

        pub fn occurrence(
            self: *const Self,
            id: CorrelationEvidenceOccurrenceId,
        ) ?OccurrenceView {
            if (id.index >= self.occurrence_count) {
                return null;
            }

            const stored =
                self.occurrences[id.index];

            return .{
                .id = id,
                .value_id = stored.value_id,
                .contributions = self.contributions[stored.contribution_start .. stored.contribution_start +
                    stored.contribution_count],
            };
        }
    };
}

test "repeated evidence value keeps distinct capture occurrences" {
    var inventory =
        CorrelationEvidenceOccurrenceInventory(4, 4){};

    const value_id: correlation.EvidenceValueId = .{
        .index = 7,
    };

    const first_contributions = [_]capture_lineage.EvidencePayloadContribution{
        .{
            .frame_occurrence = .{
                .index = 100,
            },
            .evidence_offset = 0,
            .byte_length = 4,
        },
    };

    const second_contributions = [_]capture_lineage.EvidencePayloadContribution{
        .{
            .frame_occurrence = .{
                .index = 200,
            },
            .evidence_offset = 0,
            .byte_length = 4,
        },
    };

    const first_id =
        try inventory.record(
            value_id,
            &first_contributions,
        );

    const second_id =
        try inventory.record(
            value_id,
            &second_contributions,
        );

    try std.testing.expect(
        !first_id.eql(second_id),
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        inventory.count(),
    );

    const first =
        inventory.occurrence(first_id) orelse
        return error.TestUnexpectedResult;

    const second =
        inventory.occurrence(second_id) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(
        first.value_id.eql(second.value_id),
    );

    try std.testing.expectEqual(
        @as(usize, 100),
        first.contributions[0].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 200),
        second.contributions[0].frame_occurrence.index,
    );
}

test "evidence occurrence preserves multiple payload contributors" {
    var inventory =
        CorrelationEvidenceOccurrenceInventory(2, 8){};

    const contributions = [_]capture_lineage.EvidencePayloadContribution{
        .{
            .frame_occurrence = .{ .index = 82347 },
            .evidence_offset = 0,
            .byte_length = 3,
        },
        .{
            .frame_occurrence = .{ .index = 82351 },
            .evidence_offset = 3,
            .byte_length = 7,
        },
        .{
            .frame_occurrence = .{ .index = 82353 },
            .evidence_offset = 10,
            .byte_length = 7,
        },
        .{
            .frame_occurrence = .{ .index = 82367 },
            .evidence_offset = 17,
            .byte_length = 7,
        },
        .{
            .frame_occurrence = .{ .index = 82369 },
            .evidence_offset = 24,
            .byte_length = 7,
        },
        .{
            .frame_occurrence = .{ .index = 82371 },
            .evidence_offset = 31,
            .byte_length = 2,
        },
    };

    const id =
        try inventory.record(
            .{ .index = 1 },
            &contributions,
        );

    const occurrence =
        inventory.occurrence(id) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(usize, 6),
        occurrence.contributions.len,
    );

    try std.testing.expectEqual(
        @as(usize, 33),
        occurrence.contributions[5].evidence_offset +
            occurrence.contributions[5].byte_length,
    );
}

test "evidence occurrence requires payload provenance" {
    var inventory =
        CorrelationEvidenceOccurrenceInventory(1, 1){};

    try std.testing.expectError(
        error.CorrelationEvidenceOccurrenceRequiresContribution,
        inventory.record(
            .{ .index = 0 },
            &.{},
        ),
    );
}

test "cross-protocol relationship preserves independent occurrence lineage" {
    const Evidence =
        correlation.OwnedCorrelationEvidence(64);

    const payload =
        "DTDSC*471N10*S0066951*611035\x00\x00\x00\x00*";

    var evidence_inventory =
        correlation.CorrelationEvidenceInventory(
            4,
            64,
        ){};

    const j1939_evidence =
        (try Evidence.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "DTDSC",
            .model = "471N10",
            .serial_number = "S0066951",
            .unit_number = payload[22..32],
            .raw_payload = payload[0..],
        })) orelse
        return error.TestUnexpectedResult;

    const j1939_observed =
        try evidence_inventory.observe(
            j1939_evidence,
        );

    const uds_evidence =
        try Evidence.fromUdsDataIdentifier(.{
            .source_address = 0x00,
            .destination_address = 0xf1,
            .delivery = .multi_frame,
            .data_identifier = 0xf157,
            .data_after_identifier = payload[0..],
        });

    const uds_observed =
        try evidence_inventory.observe(
            uds_evidence,
        );

    try std.testing.expect(
        !j1939_observed.id.eql(
            uds_observed.id,
        ),
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        evidence_inventory.count(),
    );

    const relationship =
        evidence_inventory.exactPayloadRelationship(
            j1939_observed.id,
            uds_observed.id,
        ) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        correlation.EvidenceRelationshipReason
            .exact_payload_equality,
        relationship.reason,
    );

    try std.testing.expect(
        relationship.left.eql(
            j1939_observed.id,
        ),
    );

    try std.testing.expect(
        relationship.right.eql(
            uds_observed.id,
        ),
    );

    try std.testing.expectEqual(
        payload.len,
        relationship.byte_length,
    );

    var relationship_inventory =
        correlation.EvidenceRelationshipInventory(
            2,
        ){};

    const recorded_relationship =
        try relationship_inventory.record(
            relationship,
        );

    try std.testing.expectEqual(
        correlation.EvidenceRelationshipRecordStatus
            .new_relationship,
        recorded_relationship.status,
    );

    const j1939_contributions =
        [_]capture_lineage.EvidencePayloadContribution{
            .{
                .frame_occurrence = .{ .index = 10 },
                .evidence_offset = 0,
                .byte_length = 7,
            },
            .{
                .frame_occurrence = .{ .index = 11 },
                .evidence_offset = 7,
                .byte_length = 7,
            },
            .{
                .frame_occurrence = .{ .index = 12 },
                .evidence_offset = 14,
                .byte_length = 7,
            },
            .{
                .frame_occurrence = .{ .index = 13 },
                .evidence_offset = 21,
                .byte_length = 7,
            },
            .{
                .frame_occurrence = .{ .index = 14 },
                .evidence_offset = 28,
                .byte_length = 5,
            },
        };

    const uds_contributions =
        [_]capture_lineage.EvidencePayloadContribution{
            .{
                .frame_occurrence = .{ .index = 20 },
                .evidence_offset = 0,
                .byte_length = 3,
            },
            .{
                .frame_occurrence = .{ .index = 21 },
                .evidence_offset = 3,
                .byte_length = 7,
            },
            .{
                .frame_occurrence = .{ .index = 22 },
                .evidence_offset = 10,
                .byte_length = 7,
            },
            .{
                .frame_occurrence = .{ .index = 23 },
                .evidence_offset = 17,
                .byte_length = 7,
            },
            .{
                .frame_occurrence = .{ .index = 24 },
                .evidence_offset = 24,
                .byte_length = 7,
            },
            .{
                .frame_occurrence = .{ .index = 25 },
                .evidence_offset = 31,
                .byte_length = 2,
            },
        };

    var occurrence_inventory =
        CorrelationEvidenceOccurrenceInventory(
            4,
            16,
        ){};

    const j1939_occurrence_id =
        try occurrence_inventory.record(
            j1939_observed.id,
            &j1939_contributions,
        );

    const uds_occurrence_id =
        try occurrence_inventory.record(
            uds_observed.id,
            &uds_contributions,
        );

    const j1939_occurrence =
        occurrence_inventory.occurrence(
            j1939_occurrence_id,
        ) orelse
        return error.TestUnexpectedResult;

    const uds_occurrence =
        occurrence_inventory.occurrence(
            uds_occurrence_id,
        ) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(
        j1939_occurrence.value_id.eql(
            relationship.left,
        ),
    );

    try std.testing.expect(
        uds_occurrence.value_id.eql(
            relationship.right,
        ),
    );

    try std.testing.expectEqual(
        @as(usize, 5),
        j1939_occurrence.contributions.len,
    );

    try std.testing.expectEqual(
        @as(usize, 6),
        uds_occurrence.contributions.len,
    );

    try std.testing.expectEqual(
        payload.len,
        j1939_occurrence.contributions[4]
            .evidence_offset +
            j1939_occurrence.contributions[4]
                .byte_length,
    );

    try std.testing.expectEqual(
        payload.len,
        uds_occurrence.contributions[5]
            .evidence_offset +
            uds_occurrence.contributions[5]
                .byte_length,
    );
}
