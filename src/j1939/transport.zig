const std = @import("std");

pub const reassembly = @import("transport_reassembly.zig");

pub const abort_control: u8 = 0xff;
pub const rts_control: u8 = 0x10;
pub const bam_control: u8 = 0x20;
pub const frame_data_length: usize = 8;

pub const ParseError = error{
    InvalidLength,
    InvalidSequenceNumber,
};

pub const ConnectionAbort = struct {
    reason: u8,
    reserved: [3]u8,
    target_pgn: u32,
};

pub const RequestToSend = struct {
    total_message_size: u16,
    packet_count: u8,
    max_packets_per_cts: u8,
    target_pgn: u32,
};

pub const BamAnnouncement = struct {
    total_message_size: u16,
    packet_count: u8,
    reserved: u8,
    target_pgn: u32,
};

pub const UnsupportedConnectionManagement = struct {
    control: u8,
    data: []const u8,
};

pub const ConnectionManagement = union(enum) {
    abort: ConnectionAbort,
    rts: RequestToSend,
    bam: BamAnnouncement,
    unsupported: UnsupportedConnectionManagement,
};

pub const DataTransfer = struct {
    sequence_number: u8,
    data: []const u8,
};

pub fn parseConnectionManagementData(
    data: []const u8,
) ParseError!ConnectionManagement {
    if (data.len != frame_data_length) {
        return error.InvalidLength;
    }

    const control = data[0];

    const total_message_size: u16 =
        @as(u16, data[1]) |
        (@as(u16, data[2]) << 8);

    const target_pgn: u32 =
        @as(u32, data[5]) |
        (@as(u32, data[6]) << 8) |
        (@as(u32, data[7]) << 16);

    return switch (control) {
        abort_control => .{
            .abort = .{
                .reason = data[1],
                .reserved = .{
                    data[2],
                    data[3],
                    data[4],
                },
                .target_pgn = target_pgn,
            },
        },

        rts_control => .{
            .rts = .{
                .total_message_size = total_message_size,
                .packet_count = data[3],
                .max_packets_per_cts = data[4],
                .target_pgn = target_pgn,
            },
        },

        bam_control => .{
            .bam = .{
                .total_message_size = total_message_size,
                .packet_count = data[3],
                .reserved = data[4],
                .target_pgn = target_pgn,
            },
        },

        else => .{
            .unsupported = .{
                .control = control,
                .data = data,
            },
        },
    };
}

pub fn parseDataTransferData(
    data: []const u8,
) ParseError!DataTransfer {
    if (data.len != frame_data_length) {
        return error.InvalidLength;
    }

    const sequence_number = data[0];

    if (sequence_number == 0) {
        return error.InvalidSequenceNumber;
    }

    return .{
        .sequence_number = sequence_number,
        .data = data[1..],
    };
}

test {
    _ = reassembly;
}

test "parses authentic connection abort data" {
    const data = [_]u8{
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xeb,
        0xfe,
        0x00,
    };

    const result =
        try parseConnectionManagementData(&data);

    switch (result) {
        .abort => |abort| {
            try std.testing.expectEqual(
                @as(u8, 0xff),
                abort.reason,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{ 0xff, 0xff, 0xff },
                &abort.reserved,
            );

            try std.testing.expectEqual(
                @as(u32, 0x00feeb),
                abort.target_pgn,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "parses BAM connection-management data" {
    const data = [_]u8{
        0x20,
        20,
        0,
        3,
        0xff,
        0xca,
        0xfe,
        0x00,
    };

    const result =
        try parseConnectionManagementData(&data);

    switch (result) {
        .bam => |bam| {
            try std.testing.expectEqual(
                @as(u16, 20),
                bam.total_message_size,
            );

            try std.testing.expectEqual(
                @as(u8, 3),
                bam.packet_count,
            );

            try std.testing.expectEqual(
                @as(u8, 0xff),
                bam.reserved,
            );

            try std.testing.expectEqual(
                @as(u32, 0x00feca),
                bam.target_pgn,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "parses authentic RTS connection-management data" {
    const data = [_]u8{
        0x10,
        0x21,
        0x00,
        0x05,
        0xff,
        0xeb,
        0xfe,
        0x00,
    };

    const result =
        try parseConnectionManagementData(&data);

    switch (result) {
        .rts => |rts| {
            try std.testing.expectEqual(
                @as(u16, 33),
                rts.total_message_size,
            );

            try std.testing.expectEqual(
                @as(u8, 5),
                rts.packet_count,
            );

            try std.testing.expectEqual(
                @as(u8, 0xff),
                rts.max_packets_per_cts,
            );

            try std.testing.expectEqual(
                @as(u32, 0x00feeb),
                rts.target_pgn,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "unsupported connection-management control remains visible" {
    const data = [_]u8{
        0x11,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };

    const result =
        try parseConnectionManagementData(&data);

    switch (result) {
        .unsupported => |unsupported| {
            try std.testing.expectEqual(
                @as(u8, 0x11),
                unsupported.control,
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

test "parses transport data packet" {
    const data = [_]u8{
        1,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
    };

    const packet =
        try parseDataTransferData(&data);

    try std.testing.expectEqual(
        @as(u8, 1),
        packet.sequence_number,
    );

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
        },
        packet.data,
    );
}

test "transport data sequence zero is invalid" {
    const data = [_]u8{
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };

    try std.testing.expectError(
        error.InvalidSequenceNumber,
        parseDataTransferData(&data),
    );
}
