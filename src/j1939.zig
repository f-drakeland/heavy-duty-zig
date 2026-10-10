const std = @import("std");
const can = @import("can.zig");

pub const transport = @import("j1939/transport.zig");
pub const dm1 = @import("j1939/dm1.zig");
pub const eec1 = @import("j1939/eec1.zig");
pub const address_claim = @import("j1939/address_claim.zig");
pub const component_identification =
    @import("j1939/component_identification.zig");

pub const pdu2_format_min: u8 = 0xf0;

pub const pgn_transport_data_transfer: u32 = 0x00eb00;
pub const pgn_transport_connection_management: u32 = 0x00ec00;
pub const pgn_address_claimed: u32 = 0x00ee00;
pub const pgn_component_identification: u32 = 0x00feeb;
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
    address_claimed,
    component_identification,
    electronic_engine_controller_1,
    diagnostic_message_1,
    unsupported: u32,
};

pub const MessageDelivery = enum {
    single_frame,
    bam,
    rts_cts,
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

pub const AddressClaimObservation = struct {
    source_address: u8,
    delivery: MessageDelivery,
    name: address_claim.Name,
};

pub const ComponentIdentificationObservation = struct {
    source_address: u8,
    delivery: MessageDelivery,
    make: []const u8,
    model: []const u8,
    serial_number: []const u8,
    unit_number: []const u8,
    /// Exact logical-message payload when original bytes are available.
    ///
    /// Null means the observation was constructed without preserved original
    /// logical-message payload evidence.
    raw_payload: ?[]const u8 = null,
};

pub const Observation = union(enum) {
    component_identification: ComponentIdentificationObservation,
    address_claim: AddressClaimObservation,
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

pub const PayloadContribution =
    transport.reassembly.PayloadContribution;

pub const TransportTransfer = struct {
    source_address: u8,
    destination_address: u8,
    target_pgn: u32,
    delivery: MessageDelivery,
};

pub const TransportPayloadDerivation = struct {
    transfer: TransportTransfer,
    contribution: PayloadContribution,
};

pub const MessageAssemblyDerivation = union(enum) {
    none,
    direct_message: PayloadContribution,
    transport_started: TransportTransfer,
    transport_payload: TransportPayloadDerivation,
    transport_context: TransportTransfer,
};

pub const BamStarted = struct {
    source_address: u8,
    target_pgn: u32,
    total_message_size: u16,
    packet_count: u8,
};

pub const TransportAborted = struct {
    source_address: u8,
    destination_address: u8,
    reason: u8,
    target_pgn: u32,
    matched_active_session: bool,
    data: []const u8,
};

pub const UnsupportedTransportControl = struct {
    source_address: u8,
    destination_address: ?u8,
    control: u8,
    data: []const u8,
};

pub const MessageAssemblyEvent = union(enum) {
    transport_aborted: TransportAborted,
    message: MessageView,
    bam_started: BamStarted,
    unsupported_transport_control: UnsupportedTransportControl,
};

pub const MessageAssemblyResult = struct {
    event: ?MessageAssemblyEvent,
    derivation: MessageAssemblyDerivation,
};

pub const MessageAssemblyError =
    error{
        InvalidBamDestination,
        InvalidDirectedTransportDestination,
        SessionCapacityExceeded,
    } ||
    transport.ParseError ||
    transport.reassembly.ReassemblyError;

pub const MessageDecodeError =
    component_identification.ParseError ||
    address_claim.ParseError ||
    dm1.PayloadError ||
    dm1.ParseError ||
    eec1.ParseError;

pub fn classifyPgn(pgn: u32) PgnClassification {
    return switch (pgn) {
        pgn_transport_data_transfer => .transport_data_transfer,

        pgn_transport_connection_management => .transport_connection_management,

        pgn_address_claimed => .address_claimed,

        pgn_component_identification => .component_identification,

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
    destination_address_value: ?u8,
    payload: []const u8,
    delivery_method: MessageDelivery,

    pub fn fromSingleFrame(
        frame: FrameView,
    ) MessageView {
        return .{
            .pgn_value = frame.identifier_info.pgn,
            .source_address_value = frame.identifier_info.source_address,
            .destination_address_value = frame.identifier_info.destination_address,
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
            .destination_address_value = 0xff,
            .payload = completed.data,
            .delivery_method = .bam,
        };
    }

    pub fn fromRtsCts(
        completed: transport.reassembly.CompletedMessage,
        destination_address: u8,
    ) MessageView {
        return .{
            .pgn_value = completed.target_pgn,
            .source_address_value = completed.source_address,
            .destination_address_value = destination_address,
            .payload = completed.data,
            .delivery_method = .rts_cts,
        };
    }

    pub fn pgn(self: MessageView) u32 {
        return self.pgn_value;
    }

    pub fn sourceAddress(self: MessageView) u8 {
        return self.source_address_value;
    }

    /// Returns the destination address observed for message delivery.
    ///
    /// For a single-frame PDU1 message, this is the identifier destination.
    /// For a single-frame PDU2 message, there is no destination and this is null.
    /// For BAM, this is the transport broadcast destination 0xff.
    /// For RTS/CTS, this is the directed transport destination.
    pub fn destinationAddress(
        self: MessageView,
    ) ?u8 {
        return self.destination_address_value;
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

        const TransportSession = struct {
            occupied: bool = false,
            source_address: u8 = 0,
            destination_address: u8 = 0,
            target_pgn: u32 = 0,
            delivery: MessageDelivery = .bam,
            reassembler: Reassembler = .{},
        };

        sessions: [session_capacity]TransportSession =
            @splat(.{}),

        fn findSession(
            self: *Self,
            source_address: u8,
            destination_address: u8,
        ) ?*TransportSession {
            for (&self.sessions) |*session| {
                if (session.occupied and
                    session.source_address == source_address and
                    session.destination_address == destination_address)
                {
                    return session;
                }
            }

            return null;
        }

        fn findRtsCtsSessionForAbort(
            self: *Self,
            source_address: u8,
            destination_address: u8,
            target_pgn: u32,
        ) ?*TransportSession {
            for (&self.sessions) |*session| {
                if (!session.occupied or
                    session.delivery != .rts_cts or
                    session.target_pgn != target_pgn)
                {
                    continue;
                }

                const same_direction =
                    session.source_address == source_address and
                    session.destination_address == destination_address;

                const reverse_direction =
                    session.source_address == destination_address and
                    session.destination_address == source_address;

                if (same_direction or reverse_direction) {
                    return session;
                }
            }

            return null;
        }

        fn findFreeSession(
            self: *Self,
        ) ?*TransportSession {
            for (&self.sessions) |*session| {
                if (!session.occupied) {
                    return session;
                }
            }

            return null;
        }

        fn pushTransportConnectionManagement(
            self: *Self,
            frame: FrameView,
        ) MessageAssemblyError!MessageAssemblyResult {
            const identifier = frame.identifier();

            const connection_management =
                try transport.parseConnectionManagementData(
                    frame.data(),
                );

            switch (connection_management) {
                .abort => |abort| {
                    const destination_address =
                        identifier.destination_address orelse
                        return error.InvalidDirectedTransportDestination;

                    if (destination_address == 0xff) {
                        return error.InvalidDirectedTransportDestination;
                    }

                    const session =
                        self.findRtsCtsSessionForAbort(
                            identifier.source_address,
                            destination_address,
                            abort.target_pgn,
                        );

                    const matched_active_session =
                        session != null;

                    if (session) |active_session| {
                        active_session.reassembler.reset();
                        active_session.occupied = false;
                        active_session.source_address = 0;
                        active_session.destination_address = 0;
                        active_session.target_pgn = 0;
                        active_session.delivery = .bam;
                    }

                    return .{
                        .event = .{
                            .transport_aborted = .{
                                .source_address = identifier.source_address,
                                .destination_address = destination_address,
                                .reason = abort.reason,
                                .target_pgn = abort.target_pgn,
                                .matched_active_session = matched_active_session,
                                .data = frame.data(),
                            },
                        },
                        .derivation = .none,
                    };
                },

                .rts => |rts| {
                    const destination_address =
                        identifier.destination_address orelse
                        return error.NoActiveTransfer;

                    const session =
                        self.findSession(
                            identifier.source_address,
                            destination_address,
                        ) orelse
                        self.findFreeSession() orelse
                        return error.SessionCapacityExceeded;

                    try session.reassembler.startTransfer(
                        identifier.source_address,
                        rts.total_message_size,
                        rts.packet_count,
                        rts.target_pgn,
                    );

                    session.occupied = true;
                    session.source_address =
                        identifier.source_address;
                    session.destination_address =
                        destination_address;
                    session.target_pgn = rts.target_pgn;
                    session.delivery = .rts_cts;

                    return .{
                        .event = null,
                        .derivation = .{
                            .transport_started = .{
                                .source_address = identifier.source_address,
                                .destination_address = destination_address,
                                .target_pgn = rts.target_pgn,
                                .delivery = .rts_cts,
                            },
                        },
                    };
                },

                .cts => |cts| {
                    const derivation: MessageAssemblyDerivation =
                        blk: {
                            const destination_address =
                                identifier.destination_address orelse
                                break :blk .none;

                            const session =
                                self.findSession(
                                    destination_address,
                                    identifier.source_address,
                                ) orelse
                                break :blk .none;

                            if (session.delivery != .rts_cts) {
                                break :blk .none;
                            }

                            if (session.target_pgn != cts.target_pgn) {
                                break :blk .none;
                            }

                            break :blk .{
                                .transport_context = .{
                                    .source_address = session.source_address,
                                    .destination_address = session.destination_address,
                                    .target_pgn = session.target_pgn,
                                    .delivery = session.delivery,
                                },
                            };
                        };

                    return .{
                        .event = .{
                            .unsupported_transport_control = .{
                                .source_address = identifier.source_address,
                                .destination_address = identifier.destination_address,
                                .control = transport.cts_control,
                                .data = frame.data(),
                            },
                        },
                        .derivation = derivation,
                    };
                },

                .bam => |bam| {
                    if (identifier.destination_address !=
                        @as(?u8, 0xff))
                    {
                        return error.InvalidBamDestination;
                    }

                    const session =
                        self.findSession(
                            identifier.source_address,
                            0xff,
                        ) orelse
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
                    session.destination_address = 0xff;
                    session.target_pgn = bam.target_pgn;
                    session.delivery = .bam;

                    return .{
                        .event = .{
                            .bam_started = .{
                                .source_address = identifier.source_address,
                                .target_pgn = bam.target_pgn,
                                .total_message_size = bam.total_message_size,
                                .packet_count = bam.packet_count,
                            },
                        },
                        .derivation = .{
                            .transport_started = .{
                                .source_address = identifier.source_address,
                                .destination_address = 0xff,
                                .target_pgn = bam.target_pgn,
                                .delivery = .bam,
                            },
                        },
                    };
                },

                .unsupported => |unsupported| {
                    return .{
                        .event = .{
                            .unsupported_transport_control = .{
                                .source_address = identifier.source_address,
                                .destination_address = identifier.destination_address,
                                .control = unsupported.control,
                                .data = unsupported.data,
                            },
                        },
                        .derivation = .none,
                    };
                },
            }
        }

        fn pushTransportDataTransfer(
            self: *Self,
            frame: FrameView,
        ) MessageAssemblyError!MessageAssemblyResult {
            const identifier = frame.identifier();

            const packet =
                try transport.parseDataTransferData(
                    frame.data(),
                );

            const destination_address =
                identifier.destination_address orelse
                return error.NoActiveTransfer;

            const session =
                self.findSession(
                    identifier.source_address,
                    destination_address,
                ) orelse
                return error.NoActiveTransfer;

            const transfer = TransportTransfer{
                .source_address = session.source_address,
                .destination_address = session.destination_address,
                .target_pgn = session.target_pgn,
                .delivery = session.delivery,
            };

            const push_result =
                try session.reassembler
                    .pushDataWithContribution(
                    identifier.source_address,
                    packet.sequence_number,
                    packet.data,
                );

            var event: ?MessageAssemblyEvent = null;

            if (push_result.completed) |message| {
                const delivery = session.delivery;

                session.occupied = false;

                const logical_message = switch (delivery) {
                    .bam => MessageView.fromBam(message),

                    .rts_cts => MessageView.fromRtsCts(
                        message,
                        destination_address,
                    ),

                    .single_frame => unreachable,
                };

                event = .{
                    .message = logical_message,
                };
            }

            return .{
                .event = event,
                .derivation = .{
                    .transport_payload = .{
                        .transfer = transfer,
                        .contribution = push_result.contribution,
                    },
                },
            };
        }

        pub fn pushFrameWithDerivation(
            self: *Self,
            frame: FrameView,
        ) MessageAssemblyError!MessageAssemblyResult {
            const classification =
                frame.pgnClassification();

            switch (classification) {
                .transport_connection_management => {
                    return try self.pushTransportConnectionManagement(
                        frame,
                    );
                },

                .transport_data_transfer => {
                    return try self.pushTransportDataTransfer(
                        frame,
                    );
                },

                else => {},
            }

            const event =
                try self.pushFrame(frame);

            return .{
                .event = event,
                .derivation = .{
                    .direct_message = .{
                        .offset = 0,
                        .byte_length = frame.data().len,
                    },
                },
            };
        }

        pub fn pushFrame(
            self: *Self,
            frame: FrameView,
        ) MessageAssemblyError!?MessageAssemblyEvent {
            switch (frame.pgnClassification()) {
                .transport_connection_management => {
                    return (try self.pushTransportConnectionManagement(
                        frame,
                    )).event;
                },

                .transport_data_transfer => {
                    return (try self.pushTransportDataTransfer(
                        frame,
                    )).event;
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
                session.destination_address = 0;
                session.target_pgn = 0;
                session.delivery = .bam;
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

    const AddressClaimState = struct {
        name: address_claim.Name,
        emitted: bool = false,
    };

    const ComponentIdentificationState = struct {
        component: component_identification.ComponentIdentification,
        raw_payload: []const u8,
        emitted: bool = false,
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
        component_identification: ComponentIdentificationState,
        address_claim: AddressClaimState,
        eec1: Eec1State,
        dm1: Dm1State,
        unsupported: UnsupportedState,
    };

    pub fn init(
        message: MessageView,
    ) MessageDecodeError!MessageCursor {
        if (message.pgn() == pgn_address_claimed) {
            const name =
                try address_claim.parse(
                    message.data(),
                );

            return .{
                .source_address = message.sourceAddress(),
                .delivery_method = message.delivery(),
                .state = .{
                    .address_claim = .{
                        .name = name,
                    },
                },
            };
        }
        if (message.pgn() == pgn_component_identification) {
            const component =
                try component_identification.parse(
                    message.data(),
                );

            return .{
                .source_address = message.sourceAddress(),
                .delivery_method = message.delivery(),
                .state = .{
                    .component_identification = .{
                        .component = component,
                        .raw_payload = message.data(),
                    },
                },
            };
        }
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
            .address_claim => |*state| {
                if (state.emitted) {
                    return null;
                }

                state.emitted = true;

                return .{
                    .observation = .{
                        .address_claim = .{
                            .source_address = self.source_address,
                            .delivery = self.delivery_method,
                            .name = state.name,
                        },
                    },
                };
            },

            .component_identification => |*state| {
                if (state.emitted) {
                    return null;
                }

                state.emitted = true;

                return .{
                    .observation = .{
                        .component_identification = .{
                            .source_address = self.source_address,
                            .delivery = self.delivery_method,
                            .make = state.component.make,
                            .model = state.component.model,
                            .serial_number = state.component.serial_number,
                            .unit_number = state.component.unit_number,
                            .raw_payload = state.raw_payload,
                        },
                    },
                };
            },

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
        @as(?u8, null),
        message.destinationAddress(),
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

test "logical message view preserves single-frame PDU1 destination" {
    const payload = [_]u8{
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
    };

    const can_frame =
        try can.FrameView.fromParts(
            0x18ea0080,
            .extended,
            .data,
            8,
            &payload,
        );

    const frame =
        try FrameView.fromCanFrame(
            can_frame,
        );

    const message =
        MessageView.fromSingleFrame(
            frame,
        );

    try std.testing.expectEqual(
        @as(u32, 0x00ea00),
        message.pgn(),
    );

    try std.testing.expectEqual(
        @as(u8, 0x80),
        message.sourceAddress(),
    );

    try std.testing.expectEqual(
        @as(?u8, 0x00),
        message.destinationAddress(),
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
        @as(?u8, 0xff),
        message.destinationAddress(),
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

test "message cursor emits address claim observation" {
    const payload = [_]u8{
        0x64, 0x00, 0x40, 0x00,
        0x00, 0x03, 0x03, 0x10,
    };

    const can_frame =
        try can.FrameView.fromParts(
            0x18eeff80,
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
                .address_claim => |claim| {
                    try std.testing.expectEqual(
                        @as(u8, 0x80),
                        claim.source_address,
                    );

                    try std.testing.expectEqual(
                        MessageDelivery.single_frame,
                        claim.delivery,
                    );

                    try std.testing.expectEqual(
                        @as(u64, 0x1003030000400064),
                        claim.name.raw,
                    );

                    try std.testing.expectEqual(
                        @as(u32, 100),
                        claim.name.identityNumber(),
                    );

                    try std.testing.expectEqual(
                        @as(u16, 2),
                        claim.name.manufacturerCode(),
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

test "message assembler reports direct logical message derivation" {
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

    const result =
        try assembler.pushFrameWithDerivation(
            frame,
        );

    try std.testing.expect(
        result.event != null,
    );

    switch (result.derivation) {
        .direct_message => |contribution| {
            try std.testing.expectEqual(
                @as(usize, 0),
                contribution.offset,
            );

            try std.testing.expectEqual(
                payload.len,
                contribution.byte_length,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "message assembler reports BAM transfer start derivation" {
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
        0x18ecff80,
        .extended,
        .data,
        8,
        &bam_data,
    );

    const frame =
        try FrameView.fromCanFrame(can_frame);

    var assembler = MessageAssembler(64, 4){};

    const result =
        try assembler.pushFrameWithDerivation(
            frame,
        );

    const assembly_event =
        result.event orelse
        return error.TestUnexpectedResult;

    switch (assembly_event) {
        .bam_started => {},
        else => return error.TestUnexpectedResult,
    }

    switch (result.derivation) {
        .transport_started => |transfer| {
            try std.testing.expectEqual(
                @as(u8, 0x80),
                transfer.source_address,
            );

            try std.testing.expectEqual(
                @as(u8, 0xff),
                transfer.destination_address,
            );

            try std.testing.expectEqual(
                @as(u32, pgn_diagnostic_message_1),
                transfer.target_pgn,
            );

            try std.testing.expectEqual(
                MessageDelivery.bam,
                transfer.delivery,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "message assembler reports RTS CTS transfer start derivation" {
    const rts_data = [_]u8{
        0x10,
        0x21,
        0x00,
        0x05,
        0xff,
        0xeb,
        0xfe,
        0x00,
    };

    const can_frame = try can.FrameView.fromParts(
        0x1cecf900,
        .extended,
        .data,
        8,
        &rts_data,
    );

    const frame =
        try FrameView.fromCanFrame(can_frame);

    var assembler = MessageAssembler(64, 4){};

    const result =
        try assembler.pushFrameWithDerivation(
            frame,
        );

    try std.testing.expect(
        result.event == null,
    );

    switch (result.derivation) {
        .transport_started => |transfer| {
            try std.testing.expectEqual(
                @as(u8, 0x00),
                transfer.source_address,
            );

            try std.testing.expectEqual(
                @as(u8, 0xf9),
                transfer.destination_address,
            );

            try std.testing.expectEqual(
                @as(u32, pgn_component_identification),
                transfer.target_pgn,
            );

            try std.testing.expectEqual(
                MessageDelivery.rts_cts,
                transfer.delivery,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "message assembler reports CTS as transport context" {
    const rts_data = [_]u8{
        0x10,
        0x21,
        0x00,
        0x05,
        0xff,
        0xeb,
        0xfe,
        0x00,
    };

    const cts_data = [_]u8{
        0x11,
        0x05,
        0x01,
        0xff,
        0xff,
        0xeb,
        0xfe,
        0x00,
    };

    const rts_can_frame = try can.FrameView.fromParts(
        0x1cecf900,
        .extended,
        .data,
        8,
        &rts_data,
    );

    const cts_can_frame = try can.FrameView.fromParts(
        0x1cec00f9,
        .extended,
        .data,
        8,
        &cts_data,
    );

    const rts_frame =
        try FrameView.fromCanFrame(rts_can_frame);

    const cts_frame =
        try FrameView.fromCanFrame(cts_can_frame);

    var assembler = MessageAssembler(64, 4){};

    _ = try assembler.pushFrameWithDerivation(
        rts_frame,
    );

    const result =
        try assembler.pushFrameWithDerivation(
            cts_frame,
        );

    const event =
        result.event orelse
        return error.TestUnexpectedResult;

    switch (event) {
        .unsupported_transport_control => |unsupported| {
            try std.testing.expectEqual(
                transport.cts_control,
                unsupported.control,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    switch (result.derivation) {
        .transport_context => |transfer| {
            try std.testing.expectEqual(
                @as(u8, 0x00),
                transfer.source_address,
            );

            try std.testing.expectEqual(
                @as(u8, 0xf9),
                transfer.destination_address,
            );

            try std.testing.expectEqual(
                @as(u32, pgn_component_identification),
                transfer.target_pgn,
            );

            try std.testing.expectEqual(
                MessageDelivery.rts_cts,
                transfer.delivery,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "message assembler reports transport payload derivation" {
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

    _ = try assembler.pushFrameWithDerivation(
        bam_frame,
    );

    const first =
        try assembler.pushFrameWithDerivation(
            packet_1,
        );

    try std.testing.expect(
        first.event == null,
    );

    switch (first.derivation) {
        .transport_payload => |derivation| {
            try std.testing.expectEqual(
                @as(u8, 0x80),
                derivation.transfer.source_address,
            );

            try std.testing.expectEqual(
                @as(u8, 0xff),
                derivation.transfer.destination_address,
            );

            try std.testing.expectEqual(
                @as(u32, pgn_diagnostic_message_1),
                derivation.transfer.target_pgn,
            );

            try std.testing.expectEqual(
                MessageDelivery.bam,
                derivation.transfer.delivery,
            );

            try std.testing.expectEqual(
                @as(usize, 0),
                derivation.contribution.offset,
            );

            try std.testing.expectEqual(
                @as(usize, 7),
                derivation.contribution.byte_length,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const second =
        try assembler.pushFrameWithDerivation(
            packet_2,
        );

    try std.testing.expect(
        second.event != null,
    );

    switch (second.derivation) {
        .transport_payload => |derivation| {
            try std.testing.expectEqual(
                @as(usize, 7),
                derivation.contribution.offset,
            );

            try std.testing.expectEqual(
                @as(usize, 3),
                derivation.contribution.byte_length,
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

test "message assembler releases incomplete RTS CTS session on abort" {
    const rts_data = [_]u8{
        0x10, 0x21, 0x00, 0x05,
        0xff, 0xeb, 0xfe, 0x00,
    };

    const abort_data = [_]u8{
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xeb, 0xfe, 0x00,
    };

    const rts_can_frame = try can.FrameView.fromParts(
        0x1cecf900,
        .extended,
        .data,
        8,
        &rts_data,
    );

    // Reverse direction: receiver F9 aborts transfer from source 00.
    const abort_can_frame = try can.FrameView.fromParts(
        0x1cec00f9,
        .extended,
        .data,
        8,
        &abort_data,
    );

    const rts_frame =
        try FrameView.fromCanFrame(rts_can_frame);

    const abort_frame =
        try FrameView.fromCanFrame(abort_can_frame);

    var assembler = MessageAssembler(64, 4){};

    try std.testing.expect(
        try assembler.pushFrame(rts_frame) == null,
    );

    const abort_event =
        (try assembler.pushFrame(abort_frame)).?;

    switch (abort_event) {
        .transport_aborted => |aborted| {
            try std.testing.expectEqual(
                @as(u8, 0xf9),
                aborted.source_address,
            );

            try std.testing.expectEqual(
                @as(u8, 0x00),
                aborted.destination_address,
            );

            try std.testing.expectEqual(
                @as(u32, 0x00feeb),
                aborted.target_pgn,
            );

            try std.testing.expect(
                aborted.matched_active_session,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    // The abort must actually release the transfer state.
    try std.testing.expect(
        try assembler.pushFrame(rts_frame) == null,
    );
}

test "message assembler reconstructs authentic RTS CTS component identification transfer" {
    const rts_data = [_]u8{
        0x10, 0x21, 0x00, 0x05,
        0xff, 0xeb, 0xfe, 0x00,
    };

    const cts_data = [_]u8{
        0x11, 0x05, 0x01, 0xff,
        0xff, 0xeb, 0xfe, 0x00,
    };

    const abort_data = [_]u8{
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xeb, 0xfe, 0x00,
    };

    const packet_1_data = [_]u8{
        0x01, 0x44, 0x54, 0x44,
        0x53, 0x43, 0x2a, 0x34,
    };

    const packet_2_data = [_]u8{
        0x02, 0x37, 0x31, 0x4e,
        0x31, 0x30, 0x2a, 0x53,
    };

    const packet_3_data = [_]u8{
        0x03, 0x30, 0x30, 0x36,
        0x36, 0x39, 0x35, 0x31,
    };

    const packet_4_data = [_]u8{
        0x04, 0x2a, 0x36, 0x31,
        0x31, 0x30, 0x33, 0x35,
    };

    const packet_5_data = [_]u8{
        0x05, 0x00, 0x00, 0x00,
        0x00, 0x2a, 0xff, 0xff,
    };

    const rts_can_frame = try can.FrameView.fromParts(
        0x1cecf900,
        .extended,
        .data,
        8,
        &rts_data,
    );

    const cts_can_frame = try can.FrameView.fromParts(
        0x1cec00f9,
        .extended,
        .data,
        8,
        &cts_data,
    );

    const abort_can_frame = try can.FrameView.fromParts(
        0x1cecf900,
        .extended,
        .data,
        8,
        &abort_data,
    );

    const packet_1_can_frame = try can.FrameView.fromParts(
        0x1cebf900,
        .extended,
        .data,
        8,
        &packet_1_data,
    );

    const packet_2_can_frame = try can.FrameView.fromParts(
        0x1cebf900,
        .extended,
        .data,
        8,
        &packet_2_data,
    );

    const packet_3_can_frame = try can.FrameView.fromParts(
        0x1cebf900,
        .extended,
        .data,
        8,
        &packet_3_data,
    );

    const packet_4_can_frame = try can.FrameView.fromParts(
        0x1cebf900,
        .extended,
        .data,
        8,
        &packet_4_data,
    );

    const packet_5_can_frame = try can.FrameView.fromParts(
        0x1cebf900,
        .extended,
        .data,
        8,
        &packet_5_data,
    );

    const rts_frame =
        try FrameView.fromCanFrame(rts_can_frame);
    const cts_frame =
        try FrameView.fromCanFrame(cts_can_frame);
    const abort_frame =
        try FrameView.fromCanFrame(abort_can_frame);
    const packet_1 =
        try FrameView.fromCanFrame(packet_1_can_frame);
    const packet_2 =
        try FrameView.fromCanFrame(packet_2_can_frame);
    const packet_3 =
        try FrameView.fromCanFrame(packet_3_can_frame);
    const packet_4 =
        try FrameView.fromCanFrame(packet_4_can_frame);
    const packet_5 =
        try FrameView.fromCanFrame(packet_5_can_frame);

    var assembler = MessageAssembler(64, 4){};

    try std.testing.expect(
        try assembler.pushFrame(rts_frame) == null,
    );

    const cts_event =
        (try assembler.pushFrame(cts_frame)).?;

    switch (cts_event) {
        .unsupported_transport_control => |unsupported| {
            try std.testing.expectEqual(
                @as(u8, 0x11),
                unsupported.control,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(
        try assembler.pushFrame(packet_1) == null,
    );
    try std.testing.expect(
        try assembler.pushFrame(packet_2) == null,
    );
    try std.testing.expect(
        try assembler.pushFrame(packet_3) == null,
    );
    try std.testing.expect(
        try assembler.pushFrame(packet_4) == null,
    );

    const completed_event =
        (try assembler.pushFrame(packet_5)).?;

    const message = switch (completed_event) {
        .message => |message| message,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(
        @as(u32, 0x00feeb),
        message.pgn(),
    );

    try std.testing.expectEqual(
        @as(u8, 0x00),
        message.sourceAddress(),
    );

    try std.testing.expectEqual(
        @as(?u8, 0xf9),
        message.destinationAddress(),
    );

    try std.testing.expectEqual(
        MessageDelivery.rts_cts,
        message.delivery(),
    );

    const expected_payload = [_]u8{
        0x44, 0x54, 0x44, 0x53, 0x43, 0x2a, 0x34,
        0x37, 0x31, 0x4e, 0x31, 0x30, 0x2a, 0x53,
        0x30, 0x30, 0x36, 0x36, 0x39, 0x35, 0x31,
        0x2a, 0x36, 0x31, 0x31, 0x30, 0x33, 0x35,
        0x00, 0x00, 0x00, 0x00, 0x2a,
    };

    try std.testing.expectEqualSlices(
        u8,
        &expected_payload,
        message.data(),
    );

    var cursor =
        try MessageCursor.init(message);

    const event =
        (try cursor.next()).?;

    switch (event) {
        .observation => |observation| {
            switch (observation) {
                .component_identification => |component| {
                    try std.testing.expectEqual(
                        @as(u8, 0x00),
                        component.source_address,
                    );

                    try std.testing.expectEqual(
                        MessageDelivery.rts_cts,
                        component.delivery,
                    );

                    try std.testing.expect(
                        component.raw_payload != null,
                    );

                    try std.testing.expectEqualSlices(
                        u8,
                        &expected_payload,
                        component.raw_payload.?,
                    );

                    try std.testing.expectEqualStrings(
                        "DTDSC",
                        component.make,
                    );

                    try std.testing.expectEqualStrings(
                        "471N10",
                        component.model,
                    );

                    try std.testing.expectEqualStrings(
                        "S0066951",
                        component.serial_number,
                    );

                    const expected_unit_number = [_]u8{
                        '6',  '1',  '1',  '0',  '3', '5',
                        0x00, 0x00, 0x00, 0x00,
                    };

                    try std.testing.expectEqualSlices(
                        u8,
                        &expected_unit_number,
                        component.unit_number,
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

    const abort_event =
        (try assembler.pushFrame(abort_frame)).?;

    switch (abort_event) {
        .transport_aborted => |aborted| {
            try std.testing.expectEqual(
                @as(u8, 0x00),
                aborted.source_address,
            );

            try std.testing.expectEqual(
                @as(u8, 0xf9),
                aborted.destination_address,
            );

            try std.testing.expectEqual(
                @as(u32, 0x00feeb),
                aborted.target_pgn,
            );

            try std.testing.expect(
                !aborted.matched_active_session,
            );
        },

        else => return error.TestUnexpectedResult,
    }
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

test "classifies Address Claimed PGN" {
    const data = [_]u8{
        0x64, 0x00, 0x40, 0x00,
        0x00, 0x03, 0x03, 0x10,
    };

    const can_frame =
        try can.FrameView.fromParts(
            0x18eeff80,
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
        PgnClassification.address_claimed,
        frame.pgnClassification(),
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
