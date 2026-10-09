const std = @import("std");
const can = @import("can.zig");

pub const transport = @import("j1939/transport.zig");
pub const dm1 = @import("j1939/dm1.zig");
pub const eec1 = @import("j1939/eec1.zig");

pub const pdu2_format_min: u8 = 0xf0;

pub const pgn_transport_data_transfer: u32 = 0x00eb00;
pub const pgn_transport_connection_management: u32 = 0x00ec00;
pub const pgn_diagnostic_message_1: u32 = 0x00feca;
pub const pgn_electronic_engine_controller_1: u32 = 0x00f004;

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
    electronic_engine_controller_1,
    diagnostic_message_1,
    unsupported: u32,
};

pub const MessageDelivery = enum {
    single_frame,
    bam,
};

pub const Dm1LampObservation = struct {
    source_address: u8,
    delivery: MessageDelivery,
    statuses: dm1.LampStatuses,
    flashes: dm1.LampFlashes,
};

pub const Dm1DiagnosticTroubleCodeObservation = struct {
    source_address: u8,
    delivery: MessageDelivery,
    trouble_code: dm1.DiagnosticTroubleCode,
};

pub const Eec1EngineSpeedObservation = struct {
    source_address: u8,
    delivery: MessageDelivery,
    raw: u16,
    rpm: f64,
};

pub const Observation = union(enum) {
    eec1_engine_speed: Eec1EngineSpeedObservation,
    dm1_lamps: Dm1LampObservation,
    dm1_diagnostic_trouble_code: Dm1DiagnosticTroubleCodeObservation,
};

pub const UnsupportedMessage = struct {
    pgn: u32,
    source_address: u8,
    delivery: MessageDelivery,
    data: []const u8,
};

pub const MessageEvent = union(enum) {
    observation: Observation,
    unsupported_pgn: UnsupportedMessage,
};

pub const BamStarted = struct {
    source_address: u8,
    target_pgn: u32,
    total_message_size: u16,
    packet_count: u8,
};

pub const UnsupportedTransportControl = struct {
    source_address: u8,
    destination_address: ?u8,
    control: u8,
    data: []const u8,
};

pub const MessageAssemblyEvent = union(enum) {
    message: MessageView,
    bam_started: BamStarted,
    unsupported_transport_control: UnsupportedTransportControl,
};

pub const MessageAssemblyError =
    error{
        InvalidBamDestination,
        SessionCapacityExceeded,
    } ||
    transport.ParseError ||
    transport.reassembly.ReassemblyError;

pub const MessageDecodeError =
    dm1.PayloadError ||
    dm1.ParseError ||
    eec1.ParseError;

pub fn classifyPgn(pgn: u32) PgnClassification {
    return switch (pgn) {
        pgn_transport_data_transfer => .transport_data_transfer,

        pgn_transport_connection_management => .transport_connection_management,

        pgn_electronic_engine_controller_1 => .electronic_engine_controller_1,

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

/// Borrowed view of one complete logical J1939 message payload.
///
/// A message may have arrived in one CAN frame or may have been reconstructed
/// from J1939 transport-protocol traffic.
pub const MessageView = struct {
    pgn_value: u32,
    source_address_value: u8,
    payload: []const u8,
    delivery_method: MessageDelivery,

    pub fn fromSingleFrame(
        frame: FrameView,
    ) MessageView {
        return .{
            .pgn_value = frame.identifier_info.pgn,
            .source_address_value = frame.identifier_info.source_address,
            .payload = frame.data(),
            .delivery_method = .single_frame,
        };
    }

    pub fn fromBam(
        completed: transport.reassembly.CompletedMessage,
    ) MessageView {
        return .{
            .pgn_value = completed.target_pgn,
            .source_address_value = completed.source_address,
            .payload = completed.data,
            .delivery_method = .bam,
        };
    }

    pub fn pgn(self: MessageView) u32 {
        return self.pgn_value;
    }

    pub fn sourceAddress(self: MessageView) u8 {
        return self.source_address_value;
    }

    pub fn data(self: MessageView) []const u8 {
        return self.payload;
    }

    pub fn delivery(self: MessageView) MessageDelivery {
        return self.delivery_method;
    }
};

pub fn MessageAssembler(
    comptime message_capacity: usize,
    comptime session_capacity: usize,
) type {
    return struct {
        const Self = @This();

        const Reassembler =
            transport.reassembly.Reassembler(
                message_capacity,
            );

        const BamSession = struct {
            occupied: bool = false,
            source_address: u8 = 0,
            reassembler: Reassembler = .{},
        };

        sessions: [session_capacity]BamSession =
            @splat(.{}),

        fn findSession(
            self: *Self,
            source_address: u8,
        ) ?*BamSession {
            for (&self.sessions) |*session| {
                if (session.occupied and
                    session.source_address == source_address)
                {
                    return session;
                }
            }

            return null;
        }

        fn findFreeSession(
            self: *Self,
        ) ?*BamSession {
            for (&self.sessions) |*session| {
                if (!session.occupied) {
                    return session;
                }
            }

            return null;
        }

        pub fn pushFrame(
            self: *Self,
            frame: FrameView,
        ) MessageAssemblyError!?MessageAssemblyEvent {
            const identifier = frame.identifier();

            switch (frame.pgnClassification()) {
                .transport_connection_management => {
                    const connection_management =
                        try transport.parseConnectionManagementData(
                            frame.data(),
                        );

                    switch (connection_management) {
                        .bam => |bam| {
                            if (identifier.destination_address != @as(?u8, 0xff)) {
                                return error.InvalidBamDestination;
                            }

                            const session =
                                self.findSession(identifier.source_address) orelse
                                self.findFreeSession() orelse
                                return error.SessionCapacityExceeded;

                            try session.reassembler.startBam(
                                identifier.source_address,
                                bam.total_message_size,
                                bam.packet_count,
                                bam.target_pgn,
                            );

                            session.occupied = true;
                            session.source_address =
                                identifier.source_address;

                            return .{
                                .bam_started = .{
                                    .source_address = identifier.source_address,
                                    .target_pgn = bam.target_pgn,
                                    .total_message_size = bam.total_message_size,
                                    .packet_count = bam.packet_count,
                                },
                            };
                        },

                        .unsupported => |unsupported| {
                            return .{
                                .unsupported_transport_control = .{
                                    .source_address = identifier.source_address,
                                    .destination_address = identifier.destination_address,
                                    .control = unsupported.control,
                                    .data = unsupported.data,
                                },
                            };
                        },
                    }
                },

                .transport_data_transfer => {
                    const packet =
                        try transport.parseDataTransferData(
                            frame.data(),
                        );

                    const session =
                        self.findSession(identifier.source_address) orelse
                        return error.NoActiveTransfer;

                    const completed =
                        try session.reassembler.pushData(
                            identifier.source_address,
                            packet.sequence_number,
                            packet.data,
                        );

                    if (completed) |message| {
                        session.occupied = false;

                        return .{
                            .message = MessageView.fromBam(message),
                        };
                    }

                    return null;
                },

                else => {
                    return .{
                        .message = MessageView.fromSingleFrame(frame),
                    };
                },
            }
        }

        pub fn reset(self: *Self) void {
            for (&self.sessions) |*session| {
                session.reassembler.reset();
                session.occupied = false;
                session.source_address = 0;
            }
        }
    };
}

pub const MessageCursor = struct {
    source_address: u8,
    delivery_method: MessageDelivery,
    state: State,

    const Dm1State = struct {
        payload: dm1.PayloadView,
        iterator: dm1.DtcIterator,
        lamps_emitted: bool = false,
    };

    const Eec1State = struct {
        payload: eec1.PayloadView,
        emitted: bool = false,
    };

    const UnsupportedState = struct {
        pgn: u32,
        data: []const u8,
        emitted: bool = false,
    };

    const State = union(enum) {
        eec1: Eec1State,
        dm1: Dm1State,
        unsupported: UnsupportedState,
    };

    pub fn init(
        message: MessageView,
    ) MessageDecodeError!MessageCursor {
        if (message.pgn() == pgn_electronic_engine_controller_1) {
            const payload =
                try eec1.PayloadView.fromData(
                    message.data(),
                );

            return .{
                .source_address = message.sourceAddress(),
                .delivery_method = message.delivery(),
                .state = .{
                    .eec1 = .{
                        .payload = payload,
                    },
                },
            };
        }
        if (message.pgn() != pgn_diagnostic_message_1) {
            return .{
                .source_address = message.sourceAddress(),
                .delivery_method = message.delivery(),
                .state = .{
                    .unsupported = .{
                        .pgn = message.pgn(),
                        .data = message.data(),
                    },
                },
            };
        }

        const payload =
            try dm1.PayloadView.fromBytes(
                message.data(),
            );

        return .{
            .source_address = message.sourceAddress(),
            .delivery_method = message.delivery(),
            .state = .{
                .dm1 = .{
                    .payload = payload,
                    .iterator = payload.dtcs(),
                },
            },
        };
    }

    pub fn next(
        self: *MessageCursor,
    ) MessageDecodeError!?MessageEvent {
        switch (self.state) {
            .eec1 => |*state| {
                if (state.emitted) {
                    return null;
                }

                state.emitted = true;

                const raw =
                    state.payload.engineSpeedRaw() orelse
                    return null;

                const rpm =
                    state.payload.engineSpeedRpm() orelse
                    return null;

                return .{
                    .observation = .{
                        .eec1_engine_speed = .{
                            .source_address = self.source_address,
                            .delivery = self.delivery_method,
                            .raw = raw,
                            .rpm = rpm,
                        },
                    },
                };
            },

            .unsupported => |*unsupported| {
                if (unsupported.emitted) {
                    return null;
                }

                unsupported.emitted = true;

                return .{
                    .unsupported_pgn = .{
                        .pgn = unsupported.pgn,
                        .source_address = self.source_address,
                        .delivery = self.delivery_method,
                        .data = unsupported.data,
                    },
                };
            },

            .dm1 => |*state| {
                if (!state.lamps_emitted) {
                    state.lamps_emitted = true;

                    return .{
                        .observation = .{
                            .dm1_lamps = .{
                                .source_address = self.source_address,
                                .delivery = self.delivery_method,
                                .statuses = state.payload.lampStatuses(),
                                .flashes = state.payload.lampFlashes(),
                            },
                        },
                    };
                }

                if (try state.iterator.next()) |dtc| {
                    return .{
                        .observation = .{
                            .dm1_diagnostic_trouble_code = .{
                                .source_address = self.source_address,
                                .delivery = self.delivery_method,
                                .trouble_code = dtc,
                            },
                        },
                    };
                }

                return null;
            },
        }
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
        classifyPgn(0x00f123);

    switch (classification) {
        .unsupported => |pgn| {
            try std.testing.expectEqual(
                @as(u32, 0x00f123),
                pgn,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}

test "logical message view accepts single-frame J1939 payload" {
    const payload = [_]u8{
        0x00,
        0x55,
        0x45,
        0x23,
        0xa7,
        0x0c,
        0xff,
        0xff,
    };

    const can_frame = try can.FrameView.fromParts(
        0x18feca80,
        .extended,
        .data,
        8,
        &payload,
    );

    const frame =
        try FrameView.fromCanFrame(can_frame);

    const message =
        MessageView.fromSingleFrame(frame);

    try std.testing.expectEqual(
        @as(u32, pgn_diagnostic_message_1),
        message.pgn(),
    );

    try std.testing.expectEqual(
        @as(u8, 0x80),
        message.sourceAddress(),
    );

    try std.testing.expectEqual(
        MessageDelivery.single_frame,
        message.delivery(),
    );

    try std.testing.expectEqualSlices(
        u8,
        &payload,
        message.data(),
    );
}

test "logical message view accepts BAM-reassembled payload" {
    const payload = [_]u8{
        0x00,
        0x55,
        0x45,
        0x23,
        0xa7,
        0x0c,
        0x34,
        0x12,
        0x83,
        0x02,
    };

    const completed =
        transport.reassembly.CompletedMessage{
            .source_address = 0x80,
            .target_pgn = pgn_diagnostic_message_1,
            .data = &payload,
        };

    const message =
        MessageView.fromBam(completed);

    try std.testing.expectEqual(
        @as(u32, pgn_diagnostic_message_1),
        message.pgn(),
    );

    try std.testing.expectEqual(
        @as(u8, 0x80),
        message.sourceAddress(),
    );

    try std.testing.expectEqual(
        MessageDelivery.bam,
        message.delivery(),
    );

    try std.testing.expectEqualSlices(
        u8,
        &payload,
        message.data(),
    );
}

test "DM1 logical message produces typed observations" {
    const payload = [_]u8{
        0b01_00_01_11,
        0b00_01_10_11,
        0x45,
        0x23,
        0xa7,
        0x0c,
        0xff,
        0xff,
    };

    const can_frame = try can.FrameView.fromParts(
        0x18feca80,
        .extended,
        .data,
        8,
        &payload,
    );

    const frame =
        try FrameView.fromCanFrame(can_frame);

    const message =
        MessageView.fromSingleFrame(frame);

    var cursor =
        try MessageCursor.init(message);

    const first = (try cursor.next()).?;

    switch (first) {
        .observation => |observation| {
            switch (observation) {
                .dm1_lamps => |lamps| {
                    try std.testing.expectEqual(
                        @as(u8, 0x80),
                        lamps.source_address,
                    );

                    try std.testing.expectEqual(
                        MessageDelivery.single_frame,
                        lamps.delivery,
                    );

                    try std.testing.expectEqual(
                        dm1.LampStatus.on,
                        lamps.statuses.malfunction_indicator,
                    );
                },

                else => return error.TestUnexpectedResult,
            }
        },

        else => return error.TestUnexpectedResult,
    }

    const second = (try cursor.next()).?;

    switch (second) {
        .observation => |observation| {
            switch (observation) {
                .dm1_diagnostic_trouble_code => |diagnostic| {
                    try std.testing.expectEqual(
                        @as(u8, 0x80),
                        diagnostic.source_address,
                    );

                    try std.testing.expectEqual(
                        @as(?u32, 0x52345),
                        diagnostic.trouble_code.spn,
                    );

                    try std.testing.expectEqual(
                        @as(u8, 7),
                        diagnostic.trouble_code.fmi,
                    );
                },

                else => return error.TestUnexpectedResult,
            }
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(
        try cursor.next() == null,
    );
}

test "unsupported logical message preserves payload evidence" {
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
        0x18f12380,
        .extended,
        .data,
        8,
        &payload,
    );

    const frame =
        try FrameView.fromCanFrame(can_frame);

    const message =
        MessageView.fromSingleFrame(frame);

    var cursor =
        try MessageCursor.init(message);

    const event = (try cursor.next()).?;

    switch (event) {
        .unsupported_pgn => |unsupported| {
            try std.testing.expectEqual(
                @as(u32, 0x00f123),
                unsupported.pgn,
            );

            try std.testing.expectEqual(
                @as(u8, 0x80),
                unsupported.source_address,
            );

            try std.testing.expectEqual(
                MessageDelivery.single_frame,
                unsupported.delivery,
            );

            try std.testing.expectEqualSlices(
                u8,
                &payload,
                unsupported.data,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(
        try cursor.next() == null,
    );
}

test "message cursor emits EEC1 engine speed observation" {
    const payload = [_]u8{
        0xff,
        0xff,
        0xff,
        0xc0,
        0x25,
        0xff,
        0xff,
        0xff,
    };

    const can_frame = try can.FrameView.fromParts(
        0x18f00480,
        .extended,
        .data,
        8,
        &payload,
    );

    const frame =
        try FrameView.fromCanFrame(can_frame);

    const message =
        MessageView.fromSingleFrame(frame);

    var cursor =
        try MessageCursor.init(message);

    const event =
        (try cursor.next()).?;

    switch (event) {
        .observation => |observation| {
            switch (observation) {
                .eec1_engine_speed => |engine_speed| {
                    try std.testing.expectEqual(
                        @as(u8, 0x80),
                        engine_speed.source_address,
                    );

                    try std.testing.expectEqual(
                        MessageDelivery.single_frame,
                        engine_speed.delivery,
                    );

                    try std.testing.expectEqual(
                        @as(u16, 0x25c0),
                        engine_speed.raw,
                    );

                    try std.testing.expectEqual(
                        @as(f64, 1208.0),
                        engine_speed.rpm,
                    );
                },

                else => return error.TestUnexpectedResult,
            }
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(
        try cursor.next() == null,
    );
}

test "message assembler routes ordinary J1939 frame to logical message" {
    const payload = [_]u8{
        0x00,
        0x55,
        0x45,
        0x23,
        0xa7,
        0x0c,
        0xff,
        0xff,
    };

    const can_frame = try can.FrameView.fromParts(
        0x18feca80,
        .extended,
        .data,
        8,
        &payload,
    );

    const frame =
        try FrameView.fromCanFrame(can_frame);

    var assembler = MessageAssembler(64, 4){};

    const event =
        (try assembler.pushFrame(frame)).?;

    switch (event) {
        .message => |message| {
            try std.testing.expectEqual(
                @as(u32, pgn_diagnostic_message_1),
                message.pgn(),
            );

            try std.testing.expectEqual(
                @as(u8, 0x80),
                message.sourceAddress(),
            );

            try std.testing.expectEqual(
                MessageDelivery.single_frame,
                message.delivery(),
            );

            try std.testing.expectEqualSlices(
                u8,
                &payload,
                message.data(),
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "message assembler reassembles BAM into logical DM1 message" {
    const bam_data = [_]u8{
        0x20,
        10,
        0,
        2,
        0xff,
        0xca,
        0xfe,
        0x00,
    };

    const packet_1_data = [_]u8{
        1,
        0x00,
        0x55,
        0x45,
        0x23,
        0xa7,
        0x0c,
        0x34,
    };

    const packet_2_data = [_]u8{
        2,
        0x12,
        0x83,
        0x02,
        0xff,
        0xff,
        0xff,
        0xff,
    };

    const bam_can_frame = try can.FrameView.fromParts(
        0x18ecff80,
        .extended,
        .data,
        8,
        &bam_data,
    );

    const packet_1_can_frame = try can.FrameView.fromParts(
        0x18ebff80,
        .extended,
        .data,
        8,
        &packet_1_data,
    );

    const packet_2_can_frame = try can.FrameView.fromParts(
        0x18ebff80,
        .extended,
        .data,
        8,
        &packet_2_data,
    );

    const bam_frame =
        try FrameView.fromCanFrame(bam_can_frame);

    const packet_1 =
        try FrameView.fromCanFrame(packet_1_can_frame);

    const packet_2 =
        try FrameView.fromCanFrame(packet_2_can_frame);

    var assembler = MessageAssembler(64, 4){};

    const start_event =
        (try assembler.pushFrame(bam_frame)).?;

    switch (start_event) {
        .bam_started => |started| {
            try std.testing.expectEqual(
                @as(u8, 0x80),
                started.source_address,
            );

            try std.testing.expectEqual(
                @as(u32, pgn_diagnostic_message_1),
                started.target_pgn,
            );

            try std.testing.expectEqual(
                @as(u16, 10),
                started.total_message_size,
            );

            try std.testing.expectEqual(
                @as(u8, 2),
                started.packet_count,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(
        try assembler.pushFrame(packet_1) == null,
    );

    const completed_event =
        (try assembler.pushFrame(packet_2)).?;

    const message = switch (completed_event) {
        .message => |message| message,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(
        @as(u32, pgn_diagnostic_message_1),
        message.pgn(),
    );

    try std.testing.expectEqual(
        @as(u8, 0x80),
        message.sourceAddress(),
    );

    try std.testing.expectEqual(
        MessageDelivery.bam,
        message.delivery(),
    );

    const expected_payload = [_]u8{
        0x00,
        0x55,
        0x45,
        0x23,
        0xa7,
        0x0c,
        0x34,
        0x12,
        0x83,
        0x02,
    };

    try std.testing.expectEqualSlices(
        u8,
        &expected_payload,
        message.data(),
    );

    var cursor =
        try MessageCursor.init(message);

    _ = (try cursor.next()).?; // lamp observation

    const first_dtc_event =
        (try cursor.next()).?;

    switch (first_dtc_event) {
        .observation => |observation| {
            switch (observation) {
                .dm1_diagnostic_trouble_code => |diagnostic| {
                    try std.testing.expectEqual(
                        MessageDelivery.bam,
                        diagnostic.delivery,
                    );

                    try std.testing.expectEqual(
                        @as(?u32, 0x52345),
                        diagnostic.trouble_code.spn,
                    );
                },

                else => return error.TestUnexpectedResult,
            }
        },

        else => return error.TestUnexpectedResult,
    }

    const second_dtc_event =
        (try cursor.next()).?;

    switch (second_dtc_event) {
        .observation => |observation| {
            switch (observation) {
                .dm1_diagnostic_trouble_code => |diagnostic| {
                    try std.testing.expectEqual(
                        @as(?u32, 0x41234),
                        diagnostic.trouble_code.spn,
                    );
                },

                else => return error.TestUnexpectedResult,
            }
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(
        try cursor.next() == null,
    );
}

test "rejects BAM announcement that is not globally addressed" {
    const bam_data = [_]u8{
        0x20,
        10,
        0,
        2,
        0xff,
        0xca,
        0xfe,
        0x00,
    };

    const can_frame = try can.FrameView.fromParts(
        0x18ec0180,
        .extended,
        .data,
        8,
        &bam_data,
    );

    const frame =
        try FrameView.fromCanFrame(can_frame);

    var assembler = MessageAssembler(64, 4){};

    try std.testing.expectError(
        error.InvalidBamDestination,
        assembler.pushFrame(frame),
    );
}

test "message assembler keeps overlapping BAM sessions isolated by source" {
    const bam_a_data = [_]u8{
        0x20,
        10,
        0,
        2,
        0xff,
        0xeb,
        0xfe,
        0x00,
    };

    const bam_b_data = [_]u8{
        0x20,
        10,
        0,
        2,
        0xff,
        0xe3,
        0xfe,
        0x00,
    };

    const a_packet_1_data = [_]u8{
        1,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
    };

    const a_packet_2_data = [_]u8{
        2,
        0x08,
        0x09,
        0x0a,
        0xff,
        0xff,
        0xff,
        0xff,
    };

    const b_packet_1_data = [_]u8{
        1,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
    };

    const b_packet_2_data = [_]u8{
        2,
        0x18,
        0x19,
        0x1a,
        0xff,
        0xff,
        0xff,
        0xff,
    };

    const bam_a = try FrameView.fromCanFrame(
        try can.FrameView.fromParts(
            0x18ecff31,
            .extended,
            .data,
            8,
            &bam_a_data,
        ),
    );

    const bam_b = try FrameView.fromCanFrame(
        try can.FrameView.fromParts(
            0x18ecff0b,
            .extended,
            .data,
            8,
            &bam_b_data,
        ),
    );

    const a_packet_1 = try FrameView.fromCanFrame(
        try can.FrameView.fromParts(
            0x18ebff31,
            .extended,
            .data,
            8,
            &a_packet_1_data,
        ),
    );

    const a_packet_2 = try FrameView.fromCanFrame(
        try can.FrameView.fromParts(
            0x18ebff31,
            .extended,
            .data,
            8,
            &a_packet_2_data,
        ),
    );

    const b_packet_1 = try FrameView.fromCanFrame(
        try can.FrameView.fromParts(
            0x18ebff0b,
            .extended,
            .data,
            8,
            &b_packet_1_data,
        ),
    );

    const b_packet_2 = try FrameView.fromCanFrame(
        try can.FrameView.fromParts(
            0x18ebff0b,
            .extended,
            .data,
            8,
            &b_packet_2_data,
        ),
    );

    var assembler = MessageAssembler(64, 2){};

    _ = (try assembler.pushFrame(bam_a)).?;
    _ = (try assembler.pushFrame(bam_b)).?;

    try std.testing.expect(
        try assembler.pushFrame(a_packet_1) == null,
    );

    try std.testing.expect(
        try assembler.pushFrame(b_packet_1) == null,
    );

    const b_completed =
        (try assembler.pushFrame(b_packet_2)).?;

    const b_message = switch (b_completed) {
        .message => |message| message,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(
        @as(u8, 0x0b),
        b_message.sourceAddress(),
    );

    try std.testing.expectEqual(
        @as(u32, 0x00fee3),
        b_message.pgn(),
    );

    const a_completed =
        (try assembler.pushFrame(a_packet_2)).?;

    const a_message = switch (a_completed) {
        .message => |message| message,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(
        @as(u8, 0x31),
        a_message.sourceAddress(),
    );

    try std.testing.expectEqual(
        @as(u32, 0x00feeb),
        a_message.pgn(),
    );
}

test "classifies EEC1 PGN" {
    const data = [_]u8{
        0xff,
        0xff,
        0xff,
        0x00,
        0x20,
        0xff,
        0xff,
        0xff,
    };

    const can_frame =
        try can.FrameView.fromParts(
            0x18f00400,
            .extended,
            .data,
            8,
            &data,
        );

    const frame =
        try FrameView.fromCanFrame(
            can_frame,
        );

    try std.testing.expectEqual(
        PgnClassification.electronic_engine_controller_1,
        frame.pgnClassification(),
    );
}
