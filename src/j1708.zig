const std = @import("std");

pub const FrameError = error{
    TooShort,
    InvalidChecksum,
};

/// A borrowed view of one externally delimited J1708 message.
///
/// FrameView validates properties that can be established from the supplied
/// bytes. It does not determine where the physical J1708 message boundary was.
pub const FrameView = struct {
    bytes_: []const u8,

    pub fn fromDelimited(raw: []const u8) FrameError!FrameView {
        if (raw.len < 2) return error.TooShort;

        var sum: u8 = 0;
        for (raw) |byte| {
            sum +%= byte;
        }

        if (sum != 0) return error.InvalidChecksum;

        return .{
            .bytes_ = raw,
        };
    }

    pub fn bytes(self: FrameView) []const u8 {
        return self.bytes_;
    }

    pub fn mid(self: FrameView) u8 {
        return self.bytes_[0];
    }

    pub fn checksum(self: FrameView) u8 {
        return self.bytes_[self.bytes_.len - 1];
    }
};

pub const StorageError = error{
    CapacityExceeded,
};

pub const BoundedFrameError = FrameError || StorageError;

pub fn BoundedFrame(comptime capacity: usize) type {
    if (capacity < 2) {
        @compileError("J1708 bounded frame capacity must be at least 2 bytes");
    }

    return struct {
        const Self = @This();

        storage: [capacity]u8,
        len: usize,

        pub fn fromView(frame_view: FrameView) StorageError!Self {
            const source = frame_view.bytes();

            if (source.len > capacity) {
                return error.CapacityExceeded;
            }

            var frame: Self = undefined;
            @memcpy(frame.storage[0..source.len], source);
            frame.len = source.len;

            return frame;
        }

        pub fn fromDelimited(raw: []const u8) BoundedFrameError!Self {
            const validated = try FrameView.fromDelimited(raw);
            return fromView(validated);
        }

        pub fn bytes(self: *const Self) []const u8 {
            return self.storage[0..self.len];
        }

        pub fn view(self: *const Self) FrameView {
            return FrameView.fromDelimited(self.bytes()) catch unreachable;
        }
    };
}

test "shortest checksum-valid J1708 frame" {
    const raw = [_]u8{ 128, 128 };

    const frame = try FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(@as(u8, 128), frame.mid());
    try std.testing.expectEqual(@as(u8, 128), frame.checksum());
    try std.testing.expectEqualSlices(u8, &raw, frame.bytes());
}

test "checksum-valid J1708 frame" {
    const raw = [_]u8{ 128, 194, 0, 190 };

    const frame = try FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(@as(u8, 128), frame.mid());
    try std.testing.expectEqual(@as(u8, 190), frame.checksum());
}

test "rejects frame shorter than MID and checksum" {
    const raw = [_]u8{128};

    try std.testing.expectError(
        error.TooShort,
        FrameView.fromDelimited(&raw),
    );
}

test "rejects invalid checksum" {
    const raw = [_]u8{ 128, 194, 0, 191 };

    try std.testing.expectError(
        error.InvalidChecksum,
        FrameView.fromDelimited(&raw),
    );
}

test "accepts checksum-valid frame longer than 21 bytes" {
    const raw = [_]u8{
        128,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        128,
    };

    const frame = try FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(@as(usize, 22), frame.bytes().len);
    try std.testing.expectEqual(@as(u8, 128), frame.mid());
}

test "bounded frame owns copied bytes" {
    var raw = [_]u8{ 128, 194, 0, 190 };

    const frame = try BoundedFrame(21).fromDelimited(&raw);

    raw[0] = 0;

    try std.testing.expectEqual(@as(u8, 128), frame.bytes()[0]);
    try std.testing.expectEqual(@as(u8, 128), frame.view().mid());
}

test "bounded frame reports capacity exceeded separately from protocol validity" {
    const raw = [_]u8{
        128,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        128,
    };

    const view = try FrameView.fromDelimited(&raw);

    try std.testing.expectError(
        error.CapacityExceeded,
        BoundedFrame(21).fromView(view),
    );
}

test "bounded frame can own valid frame longer than 21 bytes when capacity allows" {
    const raw = [_]u8{
        128,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        128,
    };

    const frame = try BoundedFrame(32).fromDelimited(&raw);

    try std.testing.expectEqual(@as(usize, 22), frame.bytes().len);
    try std.testing.expectEqual(@as(u8, 128), frame.view().mid());
}
