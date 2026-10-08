const std = @import("std");
const can = @import("can.zig");

pub const transport = @import("j1939/transport.zig");
pub const dm1 = @import("j1939/dm1.zig");

pub const pdu2_format_min: u8 = 0xf0;

pub const pgn_transport_data_transfer: u32 = 0x00eb00;
pub const pgn_transport_connection_management: u32 = 0x00ec00;
pub const pgn_diagnostic_message_1: u32 = 0x00feca;

pub const ParseError = error{
    StandardIdentifierNotJ1939,
    RemoteFrameNotJ1939,
};

pub const PduKind = enum {
    pdu1,
    pdu2,
};

pub const PgnClassification = union(enum) {
    transport_data_transfer,
    transport_connection_management,
    diagnostic_message_1,
    unsupported: u32,
};

pub fn classifyPgn(pgn: u32) PgnClassification {
    return switch (pgn) {
        pgn_transport_data_transfer => .transport_data_transfer,

        pgn_transport_connection_management => .transport_connection_management,

        pgn_diagnostic_message_1 => .diagnostic_message_1,

        else => .{
            .unsupported = pgn,
        },
    };
}

/// Decoded semantics of one J1939 29-bit CAN identifier.
///
/// This type describes identifier-level J1939 facts only. It does not claim
/// that HDZ understands the payload carried by the frame.
pub const Identifier = struct {
    priority: u8,
    reserved: bool,
    data_page: bool,
    pdu_format: u8,
    pdu_specific: u8,
    source_address: u8,

    pdu_kind: PduKind,
    pgn: u32,
    destination_address: ?u8,

    pub fn fromFrame(
        frame_view: can.FrameView,
    ) ParseError!Identifier {
        if (frame_view.format() != .extended) {
            return error.StandardIdentifierNotJ1939;
        }

        if (frame_view.kind() != .data) {
            return error.RemoteFrameNotJ1939;
        }

        const identifier_value = frame_view.identifier();

        const priority: u8 =
            @intCast((identifier_value >> 26) & 0x07);

        const reserved_bit =
            (identifier_value >> 25) & 0x01;

        const data_page_bit =
            (identifier_value >> 24) & 0x01;

        const pdu_format: u8 =
            @intCast((identifier_value >> 16) & 0xff);

        const pdu_specific: u8 =
            @intCast((identifier_value >> 8) & 0xff);

        const source_address: u8 =
            @intCast(identifier_value & 0xff);

        const pdu_kind: PduKind =
            if (pdu_format < pdu2_format_min)
                .pdu1
            else
                .pdu2;

        const pgn =
            (reserved_bit << 17) |
            (data_page_bit << 16) |
            (@as(u32, pdu_format) << 8) |
            if (pdu_kind == .pdu2)
                @as(u32, pdu_specific)
            else
                0;

        return .{
            .priority = priority,
            .reserved = reserved_bit != 0,
            .data_page = data_page_bit != 0,
            .pdu_format = pdu_format,
            .pdu_specific = pdu_specific,
            .source_address = source_address,

            .pdu_kind = pdu_kind,
            .pgn = pgn,
            .destination_address = if (pdu_kind == .pdu1)
                pdu_specific
            else
                null,
        };
    }
};

/// Borrowed view of one CAN data frame carrying J1939 identifier semantics.
///
/// This represents one physical CAN frame. It does not imply that the complete
/// J1939 application message fits in one frame.
pub const FrameView = struct {
    can_frame: can.FrameView,
    identifier_info: Identifier,

    pub fn fromCanFrame(
        can_frame: can.FrameView,
    ) ParseError!FrameView {
        const identifier_info =
            try Identifier.fromFrame(can_frame);

        return .{
            .can_frame = can_frame,
            .identifier_info = identifier_info,
        };
    }

    pub fn identifier(self: FrameView) Identifier {
        return self.identifier_info;
    }

    pub fn pgnClassification(
        self: FrameView,
    ) PgnClassification {
        return classifyPgn(
            self.identifier_info.pgn,
        );
    }

    pub fn data(self: FrameView) []const u8 {
        return self.can_frame.data();
    }

    pub fn underlyingCanFrame(self: FrameView) can.FrameView {
        return self.can_frame;
    }
};

test {
    _ = transport;
    _ = dm1;
}

test "parses PDU2 extended identifier" {
    const payload = [_]u8{
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };

    const frame = try can.FrameView.fromParts(
        0x18f004fe,
        .extended,
        .data,
        8,
        &payload,
    );

    const identifier = try Identifier.fromFrame(frame);

    try std.testing.expectEqual(
        @as(u8, 6),
        identifier.priority,
    );

    try std.testing.expect(!identifier.reserved);
    try std.testing.expect(!identifier.data_page);

    try std.testing.expectEqual(
        @as(u8, 0xf0),
        identifier.pdu_format,
    );

    try std.testing.expectEqual(
        @as(u8, 0x04),
        identifier.pdu_specific,
    );

    try std.testing.expectEqual(
        @as(u8, 0xfe),
        identifier.source_address,
    );

    try std.testing.expectEqual(
        PduKind.pdu2,
        identifier.pdu_kind,
    );

    try std.testing.expectEqual(
        @as(u32, 0x00f004),
        identifier.pgn,
    );

    try std.testing.expectEqual(
        @as(?u8, null),
        identifier.destination_address,
    );
}

test "PDU1 normalizes destination out of PGN" {
    const payload = [_]u8{
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };

    const frame = try can.FrameView.fromParts(
        0x18eaff00,
        .extended,
        .data,
        8,
        &payload,
    );

    const identifier = try Identifier.fromFrame(frame);

    try std.testing.expectEqual(
        PduKind.pdu1,
        identifier.pdu_kind,
    );

    try std.testing.expectEqual(
        @as(u8, 0xea),
        identifier.pdu_format,
    );

    try std.testing.expectEqual(
        @as(u8, 0xff),
        identifier.pdu_specific,
    );

    try std.testing.expectEqual(
        @as(?u8, 0xff),
        identifier.destination_address,
    );

    try std.testing.expectEqual(
        @as(u32, 0x00ea00),
        identifier.pgn,
    );

    try std.testing.expectEqual(
        @as(u8, 0x00),
        identifier.source_address,
    );
}

test "PDU format EF remains PDU1" {
    const frame = try can.FrameView.fromParts(
        0x18ef1201,
        .extended,
        .data,
        0,
        &.{},
    );

    const identifier = try Identifier.fromFrame(frame);

    try std.testing.expectEqual(
        PduKind.pdu1,
        identifier.pdu_kind,
    );

    try std.testing.expectEqual(
        @as(?u8, 0x12),
        identifier.destination_address,
    );

    try std.testing.expectEqual(
        @as(u32, 0x00ef00),
        identifier.pgn,
    );
}

test "rejects standard CAN identifier as J1939" {
    const frame = try can.FrameView.fromParts(
        0x123,
        .standard,
        .data,
        0,
        &.{},
    );

    try std.testing.expectError(
        error.StandardIdentifierNotJ1939,
        Identifier.fromFrame(frame),
    );
}

test "rejects CAN remote frame as J1939" {
    const frame = try can.FrameView.fromParts(
        0x18eaff00,
        .extended,
        .remote,
        8,
        &.{},
    );

    try std.testing.expectError(
        error.RemoteFrameNotJ1939,
        Identifier.fromFrame(frame),
    );
}

test "J1939 frame view preserves identifier and CAN payload" {
    const payload = [_]u8{
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
    };

    const can_frame = try can.FrameView.fromParts(
        0x18f004fe,
        .extended,
        .data,
        8,
        &payload,
    );

    const frame = try FrameView.fromCanFrame(can_frame);
    const identifier = frame.identifier();

    try std.testing.expectEqual(
        @as(u32, 0x00f004),
        identifier.pgn,
    );

    try std.testing.expectEqual(
        @as(u8, 0xfe),
        identifier.source_address,
    );

    try std.testing.expectEqualSlices(
        u8,
        &payload,
        frame.data(),
    );

    try std.testing.expectEqual(
        @as(u32, 0x18f004fe),
        frame.underlyingCanFrame().identifier(),
    );
}

test "classifies transport protocol PGNs" {
    try std.testing.expect(
        classifyPgn(pgn_transport_data_transfer) ==
            .transport_data_transfer,
    );

    try std.testing.expect(
        classifyPgn(
            pgn_transport_connection_management,
        ) == .transport_connection_management,
    );
}

test "classifies DM1 PGN" {
    try std.testing.expect(
        classifyPgn(
            pgn_diagnostic_message_1,
        ) == .diagnostic_message_1,
    );
}

test "unsupported PGN preserves numeric value" {
    const classification =
        classifyPgn(0x00f004);

    switch (classification) {
        .unsupported => |pgn| {
            try std.testing.expectEqual(
                @as(u32, 0x00f004),
                pgn,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}
