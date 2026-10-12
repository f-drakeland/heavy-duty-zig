const std = @import("std");

pub const payload_length: usize = 3;

pub const ParseError = error{
    InvalidPayloadLength,
};

pub const Request = struct {
    requested_pgn: u32,
};

pub fn parse(
    payload: []const u8,
) ParseError!Request {
    if (payload.len != payload_length) {
        return error.InvalidPayloadLength;
    }

    return .{
        .requested_pgn = @as(u32, payload[0]) |
            (@as(u32, payload[1]) << 8) |
            (@as(u32, payload[2]) << 16),
    };
}

test "decodes authentic vehicle identification request" {
    const request =
        try parse(&.{
            0xec,
            0xfe,
            0x00,
        });

    try std.testing.expectEqual(
        @as(u32, 0x00feec),
        request.requested_pgn,
    );
}

test "decodes authentic time date request" {
    const request =
        try parse(&.{
            0xe6,
            0xfe,
            0x00,
        });

    try std.testing.expectEqual(
        @as(u32, 0x00fee6),
        request.requested_pgn,
    );
}

test "rejects invalid request payload length" {
    try std.testing.expectError(
        error.InvalidPayloadLength,
        parse(&.{
            0xec,
            0xfe,
        }),
    );

    try std.testing.expectError(
        error.InvalidPayloadLength,
        parse(&.{
            0xec,
            0xfe,
            0x00,
            0xff,
        }),
    );
}
