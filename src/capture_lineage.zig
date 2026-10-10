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
