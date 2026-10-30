const std = @import("std");
const correlation = @import("correlation.zig");
const capture_lineage = @import("capture_lineage.zig");
const evidence_lineage = @import("evidence_lineage.zig");

/// Capture-local recorder for durable evidence and its frame lineage.
/// Both inventories are checked before either is mutated.
///
/// Callers must not independently mutate the inventories while recording.
pub fn Recorder(
    comptime evidence_capacity: usize,
    comptime payload_capacity: usize,
    comptime occurrence_capacity: usize,
    comptime contribution_capacity: usize,
) type {
    const Owned = correlation.OwnedCorrelationEvidence(payload_capacity);

    return struct {
        const Self = @This();

        pub const Error =
            evidence_lineage.ProjectionError ||
            evidence_lineage.CorrelationEvidenceOccurrenceError ||
            correlation.CorrelationInventoryError ||
            error{IncompleteEvidenceCoverage};

        pub const RecordResult = struct {
            evidence: correlation.CorrelationEvidenceObserveResult,
            occurrence_id: evidence_lineage.CorrelationEvidenceOccurrenceId,
        };

        evidence_inventory: correlation.CorrelationEvidenceInventory(
            evidence_capacity,
            payload_capacity,
        ) = .{},

        evidence_occurrences: evidence_lineage.CorrelationEvidenceOccurrenceInventory(
            occurrence_capacity,
            contribution_capacity,
        ) = .{},

        /// Records a selected evidence byte range and its frame contributors.
        ///
        /// The selected evidence range must be represented exactly once,
        /// in contiguous ascending order. No partial coverage is accepted.
        ///
        /// Scratch storage belongs to the caller. Accepted lineage is copied
        /// into the occurrence inventory before returning.
        pub fn record(
            self: *Self,
            owned: Owned,
            message_lineage: []const capture_lineage.MessagePayloadContribution,
            evidence_span: correlation.PayloadRange,
            scratch: []capture_lineage.EvidencePayloadContribution,
        ) Error!RecordResult {
            const projected =
                try evidence_lineage.projectMessageContributions(
                    message_lineage,
                    evidence_span,
                    scratch,
                );

            var covered: usize = 0;

            for (projected) |piece| {
                if (piece.evidence_offset != covered or
                    piece.byte_length == 0 or
                    piece.byte_length > evidence_span.byte_length - covered)
                {
                    return error.IncompleteEvidenceCoverage;
                }

                covered += piece.byte_length;
            }

            if (covered == 0 or
                covered != evidence_span.byte_length)
            {
                return error.IncompleteEvidenceCoverage;
            }

            try self.evidence_occurrences.checkRecordCapacity(projected);
            try self.evidence_inventory.checkObserveCapacity(owned);

            // Both mutations are now infallible under this recorder's
            // exclusive, single-threaded mutation contract.
            const observed =
                self.evidence_inventory.observe(owned) catch unreachable;

            const occurrence_id =
                self.evidence_occurrences.record(
                    observed.id,
                    projected,
                ) catch unreachable;

            return .{
                .evidence = observed,
                .occurrence_id = occurrence_id,
            };
        }
    };
}

test "repeated evidence retains distinct occurrences without partial writes" {
    const TestRecorder = Recorder(1, 8, 2, 2);
    const Evidence = correlation.OwnedCorrelationEvidence(8);

    var recorder: TestRecorder = .{};

    const owned = (try Evidence.fromJ1939ComponentIdentification(.{
        .source_address = 0,
        .delivery = .single_frame,
        .make = "A",
        .model = "B",
        .serial_number = "",
        .unit_number = "",
        .raw_payload = "ABC",
    })).?;

    var scratch: [1]capture_lineage.EvidencePayloadContribution =
        undefined;

    const first_lineage = [_]capture_lineage.MessagePayloadContribution{
        .{
            .frame_occurrence = .{ .index = 10 },
            .message_offset = 0,
            .byte_length = 3,
        },
    };

    const second_lineage = [_]capture_lineage.MessagePayloadContribution{
        .{
            .frame_occurrence = .{ .index = 20 },
            .message_offset = 0,
            .byte_length = 3,
        },
    };

    const span: correlation.PayloadRange =
        .{ .offset = 0, .byte_length = 3 };

    const first = try recorder.record(
        owned,
        &first_lineage,
        span,
        &scratch,
    );

    const second = try recorder.record(
        owned,
        &second_lineage,
        span,
        &scratch,
    );

    try std.testing.expect(first.evidence.id.eql(second.evidence.id));
    try std.testing.expectEqual(
        @as(usize, 1),
        recorder.evidence_inventory.count(),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        recorder.evidence_occurrences.count(),
    );

    const first_occurrence =
        recorder.evidence_occurrences.occurrence(
            first.occurrence_id,
        ).?;

    const second_occurrence =
        recorder.evidence_occurrences.occurrence(
            second.occurrence_id,
        ).?;

    try std.testing.expectEqual(
        @as(usize, 10),
        first_occurrence.contributions[0].frame_occurrence.index,
    );
    try std.testing.expectEqual(
        @as(usize, 20),
        second_occurrence.contributions[0].frame_occurrence.index,
    );

    try std.testing.expectError(
        error.CorrelationEvidenceOccurrenceCapacityExceeded,
        recorder.record(owned, &first_lineage, span, &scratch),
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        recorder.evidence_inventory.evidence(first.evidence.id).?
            .occurrence_count,
    );
}

test "invalid coverage and exhausted value storage do not mutate inventories" {
    const TestRecorder = Recorder(1, 8, 3, 3);
    const Evidence = correlation.OwnedCorrelationEvidence(8);

    var recorder: TestRecorder = .{};

    const first = (try Evidence.fromJ1939ComponentIdentification(.{
        .source_address = 0,
        .delivery = .single_frame,
        .make = "",
        .model = "",
        .serial_number = "",
        .unit_number = "",
        .raw_payload = "ABC",
    })).?;

    const different = (try Evidence.fromJ1939ComponentIdentification(.{
        .source_address = 1,
        .delivery = .single_frame,
        .make = "",
        .model = "",
        .serial_number = "",
        .unit_number = "",
        .raw_payload = "XYZ",
    })).?;

    const full = [_]capture_lineage.MessagePayloadContribution{
        .{
            .frame_occurrence = .{ .index = 1 },
            .message_offset = 0,
            .byte_length = 3,
        },
    };

    const gap = [_]capture_lineage.MessagePayloadContribution{
        .{
            .frame_occurrence = .{ .index = 2 },
            .message_offset = 0,
            .byte_length = 1,
        },
        .{
            .frame_occurrence = .{ .index = 3 },
            .message_offset = 2,
            .byte_length = 1,
        },
    };

    var scratch: [3]capture_lineage.EvidencePayloadContribution =
        undefined;

    const span: correlation.PayloadRange =
        .{ .offset = 0, .byte_length = 3 };

    try std.testing.expectError(
        error.IncompleteEvidenceCoverage,
        recorder.record(first, &gap, span, &scratch),
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        recorder.evidence_inventory.count(),
    );

    _ = try recorder.record(first, &full, span, &scratch);

    try std.testing.expectError(
        error.CorrelationEvidenceCapacityExceeded,
        recorder.record(different, &full, span, &scratch),
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        recorder.evidence_inventory.count(),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        recorder.evidence_occurrences.count(),
    );
}
