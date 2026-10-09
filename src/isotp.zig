const std = @import("std");

pub const ParseError = error{
    EmptyFrame,
    UnsupportedSingleFrameEscapeLength,
    UnsupportedFirstFrameExtendedLength,
    InvalidSingleFrameLength,
    TruncatedSingleFrame,
    TruncatedFirstFrame,
    InvalidFirstFrameLength,
    TruncatedConsecutiveFrame,
    TruncatedFlowControl,
};

pub const SingleFrame = struct {
    declared_length: u8,
    payload: []const u8,
    padding: []const u8,
};

pub const FirstFrame = struct {
    message_length: u16,
    data: []const u8,
};

pub const ConsecutiveFrame = struct {
    sequence_number: u8,
    data: []const u8,
};

pub const FlowControlFrame = struct {
    flow_status: u8,
    block_size: u8,
    separation_time: u8,
    padding: []const u8,
};

pub const UnsupportedFrame = struct {
    pci_type: u8,
    data: []const u8,
};

pub const Frame = union(enum) {
    single_frame: SingleFrame,
    first_frame: FirstFrame,
    consecutive_frame: ConsecutiveFrame,
    flow_control: FlowControlFrame,
    unsupported: UnsupportedFrame,
};

/// Parses ISO-TP protocol-control information from one CAN data payload.
///
/// The caller is responsible for locating the PCI byte. This initial parser
/// models the normal-addressing shape observed in the authentic project
/// capture and does not infer CAN identifier or ECU identity semantics.
pub fn parse(
    data: []const u8,
) ParseError!Frame {
    if (data.len == 0) {
        return error.EmptyFrame;
    }

    const pci_type = data[0] >> 4;

    return switch (pci_type) {
        0x0 => parseSingleFrame(data),
        0x1 => parseFirstFrame(data),
        0x2 => parseConsecutiveFrame(data),
        0x3 => parseFlowControlFrame(data),

        else => .{
            .unsupported = .{
                .pci_type = pci_type,
                .data = data,
            },
        },
    };
}

fn parseSingleFrame(
    data: []const u8,
) ParseError!Frame {
    const declared_length =
        data[0] & 0x0f;

    // Zero is the escape-length form used by later ISO-TP variants.
    // The authentic classical-CAN capture does not require it yet.
    if (declared_length == 0) {
        return error.UnsupportedSingleFrameEscapeLength;
    }

    if (declared_length > 7) {
        return error.InvalidSingleFrameLength;
    }

    const payload_length: usize =
        declared_length;

    if (data.len < 1 + payload_length) {
        return error.TruncatedSingleFrame;
    }

    return .{
        .single_frame = .{
            .declared_length = declared_length,
            .payload = data[1 .. 1 + payload_length],
            .padding = data[1 + payload_length ..],
        },
    };
}

fn parseFirstFrame(
    data: []const u8,
) ParseError!Frame {
    if (data.len < 3) {
        return error.TruncatedFirstFrame;
    }

    const message_length =
        (@as(u16, data[0] & 0x0f) << 8) |
        @as(u16, data[1]);

    if (message_length == 0) {
        return error.UnsupportedFirstFrameExtendedLength;
    }

    if (message_length <= 7) {
        return error.InvalidFirstFrameLength;
    }

    return .{
        .first_frame = .{
            .message_length = message_length,
            .data = data[2..],
        },
    };
}

fn parseConsecutiveFrame(
    data: []const u8,
) ParseError!Frame {
    if (data.len < 2) {
        return error.TruncatedConsecutiveFrame;
    }

    return .{
        .consecutive_frame = .{
            .sequence_number = data[0] & 0x0f,
            .data = data[1..],
        },
    };
}

fn parseFlowControlFrame(
    data: []const u8,
) ParseError!Frame {
    if (data.len < 3) {
        return error.TruncatedFlowControl;
    }

    return .{
        .flow_control = .{
            .flow_status = data[0] & 0x0f,
            .block_size = data[1],
            .separation_time = data[2],
            .padding = data[3..],
        },
    };
}

test "parses authentic DDEC ISO-TP single frame" {
    const data = [_]u8{
        0x02,
        0x10,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    const frame = try parse(&data);

    switch (frame) {
        .single_frame => |single| {
            try std.testing.expectEqual(
                @as(u8, 2),
                single.declared_length,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{ 0x10, 0x03 },
                single.payload,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                },
                single.padding,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "parses authentic DDEC ISO-TP first frame" {
    const data = [_]u8{
        0x10,
        0x16,
        0x62,
        0xf1,
        0x95,
        0x00,
        0x02,
        0x56,
    };

    const frame = try parse(&data);

    switch (frame) {
        .first_frame => |first| {
            try std.testing.expectEqual(
                @as(u16, 0x16),
                first.message_length,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{
                    0x62,
                    0xf1,
                    0x95,
                    0x00,
                    0x02,
                    0x56,
                },
                first.data,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "parses authentic DDEC ISO-TP consecutive frame" {
    const data = [_]u8{
        0x21,
        0x00,
        0x01,
        0x52,
        0x15,
        0x00,
        0x00,
        0x61,
    };

    const frame = try parse(&data);

    switch (frame) {
        .consecutive_frame => |consecutive| {
            try std.testing.expectEqual(
                @as(u8, 1),
                consecutive.sequence_number,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{
                    0x00,
                    0x01,
                    0x52,
                    0x15,
                    0x00,
                    0x00,
                    0x61,
                },
                consecutive.data,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "parses authentic DDEC ISO-TP flow control frame" {
    const data = [_]u8{
        0x30,
        0x08,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    const frame = try parse(&data);

    switch (frame) {
        .flow_control => |flow_control| {
            try std.testing.expectEqual(
                @as(u8, 0),
                flow_control.flow_status,
            );

            try std.testing.expectEqual(
                @as(u8, 8),
                flow_control.block_size,
            );

            try std.testing.expectEqual(
                @as(u8, 0),
                flow_control.separation_time,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "preserves unsupported PCI type" {
    const data = [_]u8{
        0x40,
        0x01,
        0x02,
    };

    const frame = try parse(&data);

    switch (frame) {
        .unsupported => |unsupported| {
            try std.testing.expectEqual(
                @as(u8, 4),
                unsupported.pci_type,
            );

            try std.testing.expectEqualSlices(
                u8,
                &data,
                unsupported.data,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "reports single-frame escape length as unsupported" {
    const data = [_]u8{
        0x00,
        0x05,
        0x10,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    try std.testing.expectError(
        error.UnsupportedSingleFrameEscapeLength,
        parse(&data),
    );
}

test "reports extended first-frame length as unsupported" {
    const data = [_]u8{
        0x10,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
        0x62,
        0xf1,
    };

    try std.testing.expectError(
        error.UnsupportedFirstFrameExtendedLength,
        parse(&data),
    );
}
