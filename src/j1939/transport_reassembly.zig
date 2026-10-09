const std = @import("std");

pub const bytes_per_packet: usize = 7;
pub const minimum_message_size: usize = 9;
pub const maximum_message_size: usize = 255 * bytes_per_packet;

pub const ReassemblyError = error{
    InvalidMessageSize,
    PacketCountMismatch,
    CapacityExceeded,
    TransferAlreadyActive,
    NoActiveTransfer,
    SourceAddressMismatch,
    UnexpectedSequenceNumber,
    InvalidPacketDataLength,
};

pub const CompletedMessage = struct {
    source_address: u8,
    target_pgn: u32,
    data: []const u8,
};

pub fn Reassembler(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        buffer: [capacity]u8 = undefined,

        active: bool = false,
        source_address: u8 = 0,
        target_pgn: u32 = 0,
        total_message_size: usize = 0,
        packet_count: u8 = 0,
        next_sequence_number: u8 = 1,
        bytes_written: usize = 0,

        pub fn reset(self: *Self) void {
            self.active = false;
            self.source_address = 0;
            self.target_pgn = 0;
            self.total_message_size = 0;
            self.packet_count = 0;
            self.next_sequence_number = 1;
            self.bytes_written = 0;
        }

        pub fn startBam(
            self: *Self,
            source_address: u8,
            total_message_size: u16,
            packet_count: u8,
            target_pgn: u32,
        ) ReassemblyError!void {
            return self.startTransfer(
                source_address,
                total_message_size,
                packet_count,
                target_pgn,
            );
        }

        pub fn startTransfer(
            self: *Self,
            source_address: u8,
            total_message_size: u16,
            packet_count: u8,
            target_pgn: u32,
        ) ReassemblyError!void {
            if (self.active) {
                return error.TransferAlreadyActive;
            }

            const message_size: usize = total_message_size;

            if (message_size < minimum_message_size or
                message_size > maximum_message_size)
            {
                return error.InvalidMessageSize;
            }

            if (message_size > capacity) {
                return error.CapacityExceeded;
            }

            const expected_packet_count =
                (message_size + bytes_per_packet - 1) /
                bytes_per_packet;

            if (packet_count != expected_packet_count) {
                return error.PacketCountMismatch;
            }

            self.active = true;
            self.source_address = source_address;
            self.target_pgn = target_pgn;
            self.total_message_size = message_size;
            self.packet_count = packet_count;
            self.next_sequence_number = 1;
            self.bytes_written = 0;
        }

        pub fn pushData(
            self: *Self,
            source_address: u8,
            sequence_number: u8,
            data: []const u8,
        ) ReassemblyError!?CompletedMessage {
            if (!self.active) {
                return error.NoActiveTransfer;
            }

            if (source_address != self.source_address) {
                return error.SourceAddressMismatch;
            }

            if (sequence_number != self.next_sequence_number) {
                return error.UnexpectedSequenceNumber;
            }

            if (data.len != bytes_per_packet) {
                return error.InvalidPacketDataLength;
            }

            const remaining =
                self.total_message_size - self.bytes_written;

            const copy_length =
                @min(remaining, data.len);

            std.mem.copyForwards(
                u8,
                self.buffer[self.bytes_written .. self.bytes_written + copy_length],
                data[0..copy_length],
            );

            self.bytes_written += copy_length;

            if (sequence_number == self.packet_count) {
                self.active = false;

                return .{
                    .source_address = self.source_address,
                    .target_pgn = self.target_pgn,
                    .data = self.buffer[0..self.total_message_size],
                };
            }

            self.next_sequence_number += 1;

            return null;
        }
    };
}

test "reassembles BAM payload and removes final packet padding" {
    var reassembler = Reassembler(32){};

    try reassembler.startBam(
        0x80,
        20,
        3,
        0x00feca,
    );

    const packet_1 = [_]u8{
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
    };

    const packet_2 = [_]u8{
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
    };

    const packet_3 = [_]u8{
        0x0f,
        0x10,
        0x11,
        0x12,
        0x13,
        0xff,
        0xff,
    };

    try std.testing.expect(
        try reassembler.pushData(
            0x80,
            1,
            &packet_1,
        ) == null,
    );

    try std.testing.expect(
        try reassembler.pushData(
            0x80,
            2,
            &packet_2,
        ) == null,
    );

    const completed =
        (try reassembler.pushData(
            0x80,
            3,
            &packet_3,
        )).?;

    try std.testing.expectEqual(
        @as(u8, 0x80),
        completed.source_address,
    );

    try std.testing.expectEqual(
        @as(u32, 0x00feca),
        completed.target_pgn,
    );

    try std.testing.expectEqual(
        @as(usize, 20),
        completed.data.len,
    );

    const expected = [_]u8{
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
        0x11,
        0x12,
        0x13,
        0xff,
    };

    try std.testing.expectEqualSlices(
        u8,
        &expected,
        completed.data,
    );
}

test "rejects BAM packet count inconsistent with message size" {
    var reassembler = Reassembler(32){};

    try std.testing.expectError(
        error.PacketCountMismatch,
        reassembler.startBam(
            0x80,
            20,
            2,
            0x00feca,
        ),
    );
}

test "rejects out-of-order transport data packet" {
    var reassembler = Reassembler(32){};

    try reassembler.startBam(
        0x80,
        20,
        3,
        0x00feca,
    );

    const packet = [_]u8{
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
    };

    try std.testing.expectError(
        error.UnexpectedSequenceNumber,
        reassembler.pushData(
            0x80,
            2,
            &packet,
        ),
    );
}

test "rejects transport data from different source address" {
    var reassembler = Reassembler(32){};

    try reassembler.startBam(
        0x80,
        20,
        3,
        0x00feca,
    );

    const packet = [_]u8{
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
    };

    try std.testing.expectError(
        error.SourceAddressMismatch,
        reassembler.pushData(
            0x81,
            1,
            &packet,
        ),
    );
}

test "reset permits recovery from incomplete BAM transfer" {
    var reassembler = Reassembler(32){};

    try reassembler.startBam(
        0x80,
        20,
        3,
        0x00feca,
    );

    const packet = [_]u8{
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
    };

    try std.testing.expectError(
        error.UnexpectedSequenceNumber,
        reassembler.pushData(
            0x80,
            2,
            &packet,
        ),
    );

    reassembler.reset();

    try reassembler.startBam(
        0x81,
        20,
        3,
        0x00feca,
    );

    try std.testing.expect(
        try reassembler.pushData(
            0x81,
            1,
            &packet,
        ) == null,
    );
}
