const std = @import("std");

pub const payload_length: usize = 8;

pub const ParseError = error{
    InvalidPayloadLength,
};

pub const PayloadView = struct {
    raw: []const u8,

    pub fn fromData(
        data: []const u8,
    ) ParseError!PayloadView {
        if (data.len != payload_length) {
            return error.InvalidPayloadLength;
        }

        return .{
            .raw = data,
        };
    }

    pub fn engineSpeedRaw(
        self: PayloadView,
    ) ?u16 {
        const raw =
            @as(u16, self.raw[3]) |
            (@as(u16, self.raw[4]) << 8);

        if (raw == 0xffff) {
            return null;
        }

        return raw;
    }

    pub fn engineSpeedRpm(
        self: PayloadView,
    ) ?f64 {
        const raw =
            self.engineSpeedRaw() orelse
            return null;

        return @as(
            f64,
            @floatFromInt(raw),
        ) * 0.125;
    }
};

test "decodes EEC1 engine speed" {
    const data = [_]u8{
        0xff,
        0xff,
        0xff,
        0xc0,
        0x25,
        0xff,
        0xff,
        0xff,
    };

    const payload =
        try PayloadView.fromData(&data);

    try std.testing.expectEqual(
        @as(?u16, 0x25c0),
        payload.engineSpeedRaw(),
    );

    try std.testing.expectEqual(
        @as(?f64, 1208.0),
        payload.engineSpeedRpm(),
    );
}

test "preserves unavailable engine speed" {
    const data = [_]u8{
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
    };

    const payload =
        try PayloadView.fromData(&data);

    try std.testing.expectEqual(
        @as(?u16, null),
        payload.engineSpeedRaw(),
    );

    try std.testing.expectEqual(
        @as(?f64, null),
        payload.engineSpeedRpm(),
    );
}

test "rejects invalid EEC1 payload length" {
    const data = [_]u8{
        0xff,
        0xff,
        0xff,
    };

    try std.testing.expectError(
        error.InvalidPayloadLength,
        PayloadView.fromData(&data),
    );
}
