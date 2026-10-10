const std = @import("std");
const correlation = @import("correlation.zig");
const capture_lineage = @import("capture_lineage.zig");

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
