const std = @import("std");
const j1708 = @import("../j1708.zig");

pub const ParameterKind = enum {
    standard,
    data_link_escape,
};

pub const Parameter = struct {
    source_mid: u8,
    pid: u16,
    data: []const u8,
    kind: ParameterKind,
};

pub const IteratorError = error{
    NotJ1587,
    MissingParameter,
    TruncatedParameter,
    MisplacedExtension,
    UnsupportedPage,
    UnsupportedParameterLayout,
};

pub const Iterator = struct {
    source_mid: u8,
    payload: []const u8,
    index: usize,
    page_index: u8,

    pub fn init(frame: j1708.FrameView) IteratorError!Iterator {
        if (frame.mid() < 128) return error.NotJ1587;

        const raw = frame.bytes();
        const payload = raw[1 .. raw.len - 1];

        if (payload.len == 0) return error.MissingParameter;

        var index: usize = 0;
        var page_index: u8 = 0;

        while (index < payload.len and payload[index] == 255) {
            if (page_index == 3) return error.UnsupportedPage;

            page_index += 1;
            index += 1;
        }

        if (index == payload.len) return error.MissingParameter;

        return .{
            .source_mid = frame.mid(),
            .payload = payload,
            .index = index,
            .page_index = page_index,
        };
    }

    pub fn next(self: *Iterator) IteratorError!?Parameter {
        if (self.index == self.payload.len) return null;

        const raw_pid = self.payload[self.index];
        self.index += 1;

        const pid =
            @as(u16, self.page_index) * 256 +
            @as(u16, raw_pid);

        switch (raw_pid) {
            0...127 => {
                const data = try self.take(1);

                return .{
                    .source_mid = self.source_mid,
                    .pid = pid,
                    .data = data,
                    .kind = .standard,
                };
            },

            128...191 => {
                const data = try self.take(2);

                return .{
                    .source_mid = self.source_mid,
                    .pid = pid,
                    .data = data,
                    .kind = .standard,
                };
            },

            192...253 => {
                if (self.index == self.payload.len) {
                    return error.TruncatedParameter;
                }

                const data_length: usize = self.payload[self.index];
                self.index += 1;

                const data = try self.take(data_length);

                return .{
                    .source_mid = self.source_mid,
                    .pid = pid,
                    .data = data,
                    .kind = .standard,
                };
            },

            254 => {
                // PID 254 and PID 510 are defined data-link escapes.
                if (self.page_index > 1) {
                    return error.UnsupportedParameterLayout;
                }

                if (self.index == self.payload.len) {
                    return error.TruncatedParameter;
                }

                const data = self.payload[self.index..];
                self.index = self.payload.len;

                return .{
                    .source_mid = self.source_mid,
                    .pid = pid,
                    .data = data,
                    .kind = .data_link_escape,
                };
            },

            255 => {
                // Extension indicators are only legal immediately after
                // the MID, where init() handles them.
                if (self.page_index < 3) {
                    return error.MisplacedExtension;
                }

                return error.UnsupportedParameterLayout;
            },
        }
    }

    fn take(self: *Iterator, count: usize) IteratorError![]const u8 {
        if (self.payload.len - self.index < count) {
            return error.TruncatedParameter;
        }

        const data = self.payload[self.index .. self.index + count];
        self.index += count;

        return data;
    }
};

test "iterates multiple J1587 parameters from one frame" {
    const raw = [_]u8{
        128,
        84,
        1,
        91,
        2,
        92,
        3,
        190,
        4,
        5,
        168,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);
    var iterator = try Iterator.init(frame);

    const first = (try iterator.next()).?;
    try std.testing.expectEqual(@as(u16, 84), first.pid);
    try std.testing.expectEqualSlices(u8, &[_]u8{1}, first.data);

    const second = (try iterator.next()).?;
    try std.testing.expectEqual(@as(u16, 91), second.pid);

    const third = (try iterator.next()).?;
    try std.testing.expectEqual(@as(u16, 92), third.pid);

    const fourth = (try iterator.next()).?;
    try std.testing.expectEqual(@as(u16, 190), fourth.pid);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 4, 5 }, fourth.data);

    try std.testing.expect((try iterator.next()) == null);
}

test "iterates variable-length parameter" {
    const raw = [_]u8{
        128,
        245,
        4,
        1,
        2,
        3,
        4,
        125,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);
    var iterator = try Iterator.init(frame);

    const parameter = (try iterator.next()).?;

    try std.testing.expectEqual(@as(u16, 245), parameter.pid);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 1, 2, 3, 4 },
        parameter.data,
    );
}

test "normalizes page two PID" {
    const raw = [_]u8{
        128,
        255,
        0,
        7,
        122,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);
    var iterator = try Iterator.init(frame);

    const parameter = (try iterator.next()).?;

    try std.testing.expectEqual(@as(u16, 256), parameter.pid);
    try std.testing.expectEqualSlices(u8, &[_]u8{7}, parameter.data);
}

test "data-link escape consumes remaining message data" {
    const raw = [_]u8{
        128,
        254,
        171,
        1,
        2,
        212,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);
    var iterator = try Iterator.init(frame);

    const parameter = (try iterator.next()).?;

    try std.testing.expectEqual(@as(u16, 254), parameter.pid);
    try std.testing.expectEqual(
        ParameterKind.data_link_escape,
        parameter.kind,
    );
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 171, 1, 2 },
        parameter.data,
    );

    try std.testing.expect((try iterator.next()) == null);
}

test "rejects misplaced extension PID" {
    const raw = [_]u8{
        128,
        84,
        1,
        255,
        44,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);
    var iterator = try Iterator.init(frame);

    _ = try iterator.next();

    try std.testing.expectError(
        error.MisplacedExtension,
        iterator.next(),
    );
}
