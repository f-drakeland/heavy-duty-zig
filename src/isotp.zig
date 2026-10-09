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

pub const MessageDelivery = enum {
    single_frame,
    multi_frame,
};

pub const CompletedMessage = struct {
    payload: []const u8,
    delivery: MessageDelivery,
};

pub const ReassemblyError = error{
    CapacityExceeded,
    TransferAlreadyActive,
    NoActiveTransfer,
    UnexpectedSequenceNumber,
    UnsupportedFrameType,
};

/// Bounded passive reassembly for one directional ISO-TP stream.
///
/// Session/address routing belongs to the caller. This type only reconstructs
/// the ISO-TP payload carried by an already-selected stream.
pub fn Reassembler(
    comptime capacity: usize,
) type {
    return struct {
        const Self = @This();

        buffer: [capacity]u8 = undefined,

        active: bool = false,
        message_length: usize = 0,
        bytes_written: usize = 0,
        next_sequence_number: u8 = 1,

        pub fn reset(
            self: *Self,
        ) void {
            self.active = false;
            self.message_length = 0;
            self.bytes_written = 0;
            self.next_sequence_number = 1;
        }

        pub fn push(
            self: *Self,
            frame: Frame,
        ) ReassemblyError!?CompletedMessage {
            switch (frame) {
                .single_frame => |single| {
                    if (self.active) {
                        return error.TransferAlreadyActive;
                    }

                    return .{
                        .payload = single.payload,
                        .delivery = .single_frame,
                    };
                },

                .first_frame => |first| {
                    if (self.active) {
                        return error.TransferAlreadyActive;
                    }

                    const message_length: usize =
                        first.message_length;

                    if (message_length > capacity) {
                        return error.CapacityExceeded;
                    }

                    const copy_length =
                        @min(
                            message_length,
                            first.data.len,
                        );

                    std.mem.copyForwards(
                        u8,
                        self.buffer[0..copy_length],
                        first.data[0..copy_length],
                    );

                    self.active = true;
                    self.message_length = message_length;
                    self.bytes_written = copy_length;
                    self.next_sequence_number = 1;

                    if (self.bytes_written ==
                        self.message_length)
                    {
                        self.active = false;

                        return .{
                            .payload = self.buffer[0..self.message_length],
                            .delivery = .multi_frame,
                        };
                    }

                    return null;
                },

                .consecutive_frame => |consecutive| {
                    if (!self.active) {
                        return error.NoActiveTransfer;
                    }

                    if (consecutive.sequence_number !=
                        self.next_sequence_number)
                    {
                        return error.UnexpectedSequenceNumber;
                    }

                    const remaining =
                        self.message_length -
                        self.bytes_written;

                    const copy_length =
                        @min(
                            remaining,
                            consecutive.data.len,
                        );

                    std.mem.copyForwards(
                        u8,
                        self.buffer[self.bytes_written .. self.bytes_written +
                            copy_length],
                        consecutive.data[0..copy_length],
                    );

                    self.bytes_written += copy_length;

                    if (self.bytes_written ==
                        self.message_length)
                    {
                        self.active = false;

                        return .{
                            .payload = self.buffer[0..self.message_length],
                            .delivery = .multi_frame,
                        };
                    }

                    self.next_sequence_number =
                        (self.next_sequence_number + 1) &
                        0x0f;

                    return null;
                },

                .flow_control => {
                    return null;
                },

                .unsupported => {
                    return error.UnsupportedFrameType;
                },
            }
        }
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

test "reassembles authentic DDEC ISO-TP response" {
    const first_data = [_]u8{
        0x10, 0x16, 0x62, 0xf1,
        0x95, 0x00, 0x02, 0x56,
    };

    const consecutive_1_data = [_]u8{
        0x21, 0x00, 0x01, 0x52,
        0x15, 0x00, 0x00, 0x61,
    };

    const consecutive_2_data = [_]u8{
        0x22, 0x0a, 0x01, 0x0a,
        0x03, 0x0a, 0x0c, 0x00,
    };

    const consecutive_3_data = [_]u8{
        0x23, 0x00, 0x00, 0x0a,
        0x03, 0x0a, 0x0c, 0x00,
    };

    var reassembler =
        Reassembler(64){};

    try std.testing.expect(
        try reassembler.push(
            try parse(&first_data),
        ) == null,
    );

    try std.testing.expect(
        try reassembler.push(
            try parse(&consecutive_1_data),
        ) == null,
    );

    try std.testing.expect(
        try reassembler.push(
            try parse(&consecutive_2_data),
        ) == null,
    );

    const completed =
        (try reassembler.push(
            try parse(&consecutive_3_data),
        )).?;

    try std.testing.expectEqual(
        MessageDelivery.multi_frame,
        completed.delivery,
    );

    const expected = [_]u8{
        0x62, 0xf1, 0x95, 0x00,
        0x02, 0x56, 0x00, 0x01,
        0x52, 0x15, 0x00, 0x00,
        0x61, 0x0a, 0x01, 0x0a,
        0x03, 0x0a, 0x0c, 0x00,
        0x00, 0x00,
    };

    try std.testing.expectEqualSlices(
        u8,
        &expected,
        completed.payload,
    );
}

test "reassembly rejects out-of-order consecutive frame" {
    const first_data = [_]u8{
        0x10, 0x16,
        0x62, 0xf1,
        0x95, 0x00,
        0x02, 0x56,
    };

    const wrong_sequence_data = [_]u8{
        0x22,
        0x00,
        0x01,
        0x52,
        0x15,
        0x00,
        0x00,
        0x61,
    };

    var reassembler =
        Reassembler(64){};

    try std.testing.expect(
        try reassembler.push(
            try parse(&first_data),
        ) == null,
    );

    try std.testing.expectError(
        error.UnexpectedSequenceNumber,
        reassembler.push(
            try parse(&wrong_sequence_data),
        ),
    );
}

test "reassembly rejects consecutive frame without active transfer" {
    const consecutive_data = [_]u8{
        0x21,
        0x00,
        0x01,
        0x52,
        0x15,
        0x00,
        0x00,
        0x61,
    };

    var reassembler =
        Reassembler(64){};

    try std.testing.expectError(
        error.NoActiveTransfer,
        reassembler.push(
            try parse(&consecutive_data),
        ),
    );
}

test "reassembly wraps consecutive sequence number from fifteen to zero" {
    const first_data = [_]u8{
        0x10, 0x76,
        0,    0,
        0,    0,
        0,    0,
    };

    var reassembler =
        Reassembler(128){};

    try std.testing.expect(
        try reassembler.push(
            try parse(&first_data),
        ) == null,
    );

    var sequence_number: u8 = 1;
    var index: usize = 0;

    while (index < 16) : (index += 1) {
        var data = [_]u8{
            0x20,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        };

        data[0] |= sequence_number;

        const completed =
            try reassembler.push(
                try parse(&data),
            );

        if (index < 15) {
            try std.testing.expect(
                completed == null,
            );
        } else {
            try std.testing.expect(
                completed != null,
            );

            try std.testing.expectEqual(
                @as(usize, 0x76),
                completed.?.payload.len,
            );
        }

        sequence_number =
            (sequence_number + 1) & 0x0f;
    }
}
