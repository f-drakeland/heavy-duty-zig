const std = @import("std");

/// Capture-local identity of one frame occurrence.
///
/// The index is assigned by capture orchestration and is meaningful only
/// within the capture occurrence namespace that assigned it. It does not
/// encode a source line number, timestamp, protocol endpoint, controller,
/// component, vehicle, or physical-device identity.
pub const FrameOccurrenceId = struct {
    index: usize,

    pub fn eql(
        self: FrameOccurrenceId,
        other: FrameOccurrenceId,
    ) bool {
        return self.index == other.index;
    }
};

/// Records the evidence-relative bytes supplied by one frame occurrence.
///
/// This describes payload contribution only. Transport control or other
/// contextual frame occurrences are not payload contributors.
pub const EvidencePayloadContribution = struct {
    frame_occurrence: FrameOccurrenceId,
    evidence_offset: usize,
    byte_length: usize,
};

test "frame occurrence identity is capture-local index identity" {
    const first: FrameOccurrenceId = .{
        .index = 42,
    };

    const same: FrameOccurrenceId = .{
        .index = 42,
    };

    const other: FrameOccurrenceId = .{
        .index = 43,
    };

    try std.testing.expect(
        first.eql(same),
    );

    try std.testing.expect(
        !first.eql(other),
    );
}

test "evidence payload contribution keeps frame and evidence range distinct" {
    const contribution: EvidencePayloadContribution = .{
        .frame_occurrence = .{
            .index = 82347,
        },
        .evidence_offset = 0,
        .byte_length = 3,
    };

    try std.testing.expectEqual(
        @as(usize, 82347),
        contribution.frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        contribution.evidence_offset,
    );

    try std.testing.expectEqual(
        @as(usize, 3),
        contribution.byte_length,
    );
}
