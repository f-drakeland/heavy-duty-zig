const std = @import("std");

const can = @import("can.zig");
const capture_lineage = @import("capture_lineage.zig");
const ddec_csv = @import("ddec_csv.zig");
const isotp = @import("isotp.zig");
const isotp_capture_lineage =
    @import("isotp_capture_lineage.zig");
const j1939 = @import("j1939.zig");
const j1939_capture_lineage =
    @import("j1939_capture_lineage.zig");

const j1939_lineage_capacity: usize = 255;

/// Returns true for the 29-bit ISO-TP address-byte form currently
/// validated by HDZ capture evidence.
///
/// This is intentionally narrower than claiming support for every
/// ISO-TP CAN addressing form.
fn isObservedIsoTpIdentifier(
    identifier: u32,
) bool {
    return (identifier & 0x1fff0000) ==
        0x18da0000;
}

/// Single-pass CAN protocol orchestration with capture lineage.
///
/// J1939 and ISO-TP remain independent protocol interpretations.
/// This type coordinates their existing protocol state with capture
/// occurrence lineage; it does not perform evidence correlation or
/// claim physical ECU identity.
///
/// Returned messages and lineage are borrowed views.
///
/// Reassembled message payloads and lineage slices borrow pipeline-owned
/// storage and must be consumed before the next call to `push`.
///
/// Single-frame message payloads borrow the input `can.FrameView` data.
/// The caller must keep those bytes alive and unchanged while consuming
/// the returned result.
///
/// As a uniform rule, consume all returned views before modifying the
/// input frame storage or calling `push` again.
pub fn Pipeline(
    comptime j1939_session_capacity: usize,
    comptime isotp_session_capacity: usize,
    comptime isotp_payload_capacity: usize,
) type {
    if (j1939_session_capacity == 0) {
        @compileError(
            "J1939 session capacity must be greater than zero",
        );
    }

    if (isotp_session_capacity == 0) {
        @compileError(
            "ISO-TP session capacity must be greater than zero",
        );
    }

    if (isotp_payload_capacity == 0) {
        @compileError(
            "ISO-TP payload capacity must be greater than zero",
        );
    }
    // Every accepted ISO-TP payload contributor supplies at least one
    // logical-message byte. Deriving lineage capacity from payload capacity
    // therefore guarantees that every accepted message can represent all of
    // its payload contributors without a second independent storage limit.

    return struct {
        const Self = @This();

        const J1939Assembler =
            j1939.MessageAssembler(
                j1939.transport.reassembly.maximum_message_size,
                j1939_session_capacity,
            );

        const J1939Lineage =
            j1939_capture_lineage
                .J1939TransportLineageTracker(
                j1939_session_capacity,
                j1939_lineage_capacity,
            );

        const IsotpRouter =
            isotp.SessionRouter(
                isotp_session_capacity,
                isotp_payload_capacity,
            );

        const IsotpLineage =
            isotp_capture_lineage
                .IsotpTransportLineageTracker(
                isotp_session_capacity,
                isotp_payload_capacity,
            );

        pub const J1939Message = struct {
            message: j1939.MessageView,
            lineage: []const capture_lineage.MessagePayloadContribution,
        };

        pub const J1939Event = union(enum) {
            message: J1939Message,
            transport_aborted: j1939.TransportAborted,
            bam_started: j1939.BamStarted,
            unsupported_transport_control: j1939.UnsupportedTransportControl,
        };

        pub const IsotpMessage = struct {
            message: isotp.RoutedMessage,
            lineage: []const capture_lineage.MessagePayloadContribution,
        };

        pub const IsotpEvent = union(enum) {
            message: IsotpMessage,
            flow_control: isotp.RoutedFlowControl,
            unsupported_frame: isotp.UnsupportedFrame,
        };

        pub const J1939Error =
            j1939.MessageAssemblyError ||
            J1939Lineage.Error;

        pub const IsotpError =
            isotp.ParseError ||
            isotp.SessionError ||
            IsotpLineage.Error;

        pub const J1939Outcome = union(enum) {
            none,
            event: J1939Event,
            failure: J1939Error,
        };

        pub const IsotpOutcome = union(enum) {
            none,
            event: IsotpEvent,
            failure: IsotpError,
        };

        pub const PushResult = struct {
            j1939: J1939Outcome = .none,
            isotp: IsotpOutcome = .none,
        };

        j1939_assembler: J1939Assembler = .{},
        j1939_lineage: J1939Lineage = .{},

        isotp_router: IsotpRouter = .{},
        isotp_lineage: IsotpLineage = .{},

        j1939_completed_lineage: [j1939_lineage_capacity]capture_lineage.MessagePayloadContribution =
            undefined,

        j1939_completed_lineage_count: usize = 0,

        isotp_completed_lineage: [isotp_payload_capacity]capture_lineage.MessagePayloadContribution =
            undefined,

        isotp_completed_lineage_count: usize = 0,

        fn setJ1939DirectLineage(
            self: *Self,
            frame_occurrence: capture_lineage.FrameOccurrenceId,
            contribution: j1939.PayloadContribution,
        ) []const capture_lineage.MessagePayloadContribution {
            self.j1939_completed_lineage[0] = .{
                .frame_occurrence = frame_occurrence,
                .message_offset = contribution.offset,
                .byte_length = contribution.byte_length,
            };

            self.j1939_completed_lineage_count = 1;

            return self.j1939_completed_lineage[0..1];
        }

        fn setJ1939TransportLineage(
            self: *Self,
            contributions: []const capture_lineage.MessagePayloadContribution,
        ) J1939Error![]const capture_lineage.MessagePayloadContribution {
            if (contributions.len >
                self.j1939_completed_lineage.len)
            {
                return error.ContributionCapacityExceeded;
            }

            @memcpy(
                self.j1939_completed_lineage[0..contributions.len],
                contributions,
            );

            self.j1939_completed_lineage_count =
                contributions.len;

            return self.j1939_completed_lineage[0..self.j1939_completed_lineage_count];
        }

        fn setIsotpDirectLineage(
            self: *Self,
            frame_occurrence: capture_lineage.FrameOccurrenceId,
            contribution: isotp.PayloadContribution,
        ) []const capture_lineage.MessagePayloadContribution {
            self.isotp_completed_lineage[0] = .{
                .frame_occurrence = frame_occurrence,
                .message_offset = contribution.offset,
                .byte_length = contribution.byte_length,
            };

            self.isotp_completed_lineage_count = 1;

            return self.isotp_completed_lineage[0..1];
        }

        fn setIsotpTransportLineage(
            self: *Self,
            contributions: []const capture_lineage.MessagePayloadContribution,
        ) IsotpError![]const capture_lineage.MessagePayloadContribution {
            if (contributions.len >
                self.isotp_completed_lineage.len)
            {
                return error.ContributionCapacityExceeded;
            }

            @memcpy(
                self.isotp_completed_lineage[0..contributions.len],
                contributions,
            );

            self.isotp_completed_lineage_count =
                contributions.len;

            return self.isotp_completed_lineage[0..self.isotp_completed_lineage_count];
        }

        fn pushJ1939(
            self: *Self,
            frame_occurrence: capture_lineage.FrameOccurrenceId,
            frame: can.FrameView,
        ) J1939Error!?J1939Event {
            const j1939_frame =
                j1939.FrameView.fromCanFrame(
                    frame,
                ) catch unreachable;

            const assembly =
                try self.j1939_assembler
                    .pushFrameWithDerivation(
                    j1939_frame,
                );

            var completed_lineage: ?[]const capture_lineage.MessagePayloadContribution =
                null;

            switch (assembly.derivation) {
                .transport_started => |transfer| {
                    try self.j1939_lineage.start(
                        transfer,
                    );
                },

                .transport_payload => |derivation| {
                    try self.j1939_lineage.recordPayload(
                        frame_occurrence,
                        derivation,
                    );

                    if (assembly.event) |event| {
                        switch (event) {
                            .message => {
                                const lineage =
                                    try self.j1939_lineage.finish(
                                        derivation.transfer,
                                    );

                                completed_lineage =
                                    try self.setJ1939TransportLineage(
                                        lineage.slice(),
                                    );
                            },

                            else => {},
                        }
                    }
                },

                .direct_message => |contribution| {
                    completed_lineage =
                        self.setJ1939DirectLineage(
                            frame_occurrence,
                            contribution,
                        );
                },

                .none,
                .transport_context,
                => {},
            }

            const event =
                assembly.event orelse
                return null;

            return switch (event) {
                .message => |message| .{
                    .message = .{
                        .message = message,
                        .lineage = completed_lineage orelse
                            unreachable,
                    },
                },

                .transport_aborted => |aborted| blk: {
                    if (aborted.transfer) |transfer| {
                        try self.j1939_lineage.abort(
                            transfer,
                        );
                    }

                    break :blk .{
                        .transport_aborted = aborted,
                    };
                },

                .bam_started => |started| .{
                    .bam_started = started,
                },

                .unsupported_transport_control => |unsupported| .{
                    .unsupported_transport_control = unsupported,
                },
            };
        }

        fn pushIsotp(
            self: *Self,
            frame_occurrence: capture_lineage.FrameOccurrenceId,
            frame: can.FrameView,
        ) IsotpError!?IsotpEvent {
            const parsed =
                try isotp.parse(
                    frame.data(),
                );

            switch (parsed) {
                .unsupported => |unsupported| {
                    return .{
                        .unsupported_frame = unsupported,
                    };
                },

                else => {},
            }

            const identifier =
                frame.identifier();

            const source_address: u8 =
                @truncate(identifier);

            const destination_address: u8 =
                @truncate(identifier >> 8);

            const routed =
                try self.isotp_router
                    .pushWithDerivation(
                    source_address,
                    destination_address,
                    parsed,
                );

            var completed_lineage: ?[]const capture_lineage.MessagePayloadContribution =
                null;

            switch (routed.derivation) {
                .direct_message => |derivation| {
                    completed_lineage =
                        self.setIsotpDirectLineage(
                            frame_occurrence,
                            derivation.contribution,
                        );
                },

                .transport_started => |derivation| {
                    try self.isotp_lineage.start(
                        frame_occurrence,
                        derivation,
                    );

                    switch (routed.event) {
                        .completed => {
                            const lineage =
                                try self.isotp_lineage.finish(
                                    derivation.transfer,
                                );

                            completed_lineage =
                                try self.setIsotpTransportLineage(
                                    lineage.slice(),
                                );
                        },

                        else => {},
                    }
                },

                .transport_payload => |derivation| {
                    try self.isotp_lineage.recordPayload(
                        frame_occurrence,
                        derivation,
                    );

                    switch (routed.event) {
                        .completed => {
                            const lineage =
                                try self.isotp_lineage.finish(
                                    derivation.transfer,
                                );

                            completed_lineage =
                                try self.setIsotpTransportLineage(
                                    lineage.slice(),
                                );
                        },

                        else => {},
                    }
                },

                .none,
                .transport_context,
                => {},
            }

            return switch (routed.event) {
                .in_progress => null,

                .flow_control => |flow_control| .{
                    .flow_control = flow_control,
                },

                .completed => |message| .{
                    .message = .{
                        .message = message,
                        .lineage = completed_lineage orelse
                            unreachable,
                    },
                },
            };
        }

        pub fn push(
            self: *Self,
            frame_occurrence: capture_lineage.FrameOccurrenceId,
            frame: can.FrameView,
        ) PushResult {
            self.j1939_completed_lineage_count = 0;
            self.isotp_completed_lineage_count = 0;

            var result: PushResult = .{};

            if (frame.format() != .extended or
                frame.kind() != .data)
            {
                return result;
            }

            result.j1939 = j1939_outcome: {
                const maybe_event =
                    self.pushJ1939(
                        frame_occurrence,
                        frame,
                    ) catch |err| {
                        break :j1939_outcome .{
                            .failure = err,
                        };
                    };

                if (maybe_event) |event| {
                    break :j1939_outcome .{
                        .event = event,
                    };
                }

                break :j1939_outcome .none;
            };

            if (isObservedIsoTpIdentifier(
                frame.identifier(),
            )) {
                result.isotp = isotp_outcome: {
                    const maybe_event =
                        self.pushIsotp(
                            frame_occurrence,
                            frame,
                        ) catch |err| {
                            break :isotp_outcome .{
                                .failure = err,
                            };
                        };

                    if (maybe_event) |event| {
                        break :isotp_outcome .{
                            .event = event,
                        };
                    }

                    break :isotp_outcome .none;
                };
            }

            return result;
        }
    };
}

test "ISO-TP failure does not discard independent J1939 interpretation" {
    const TestPipeline =
        Pipeline(
            2,
            2,
            64,
        );

    var pipeline: TestPipeline = .{};

    const data = [_]u8{
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
    };

    const frame =
        try can.FrameView.fromParts(
            0x18daf100,
            .extended,
            .data,
            data.len,
            &data,
        );

    const result =
        pipeline.push(
            .{ .index = 42 },
            frame,
        );

    switch (result.j1939) {
        .event => |event| {
            switch (event) {
                .message => |completed| {
                    try std.testing.expectEqual(
                        @as(u32, 0x00da00),
                        completed.message.pgn(),
                    );

                    try std.testing.expectEqual(
                        @as(usize, 1),
                        completed.lineage.len,
                    );

                    try std.testing.expectEqual(
                        @as(usize, 42),
                        completed.lineage[0]
                            .frame_occurrence.index,
                    );
                },

                else => return error.TestUnexpectedResult,
            }
        },

        .none,
        .failure,
        => return error.TestUnexpectedResult,
    }

    switch (result.isotp) {
        .failure => |err| {
            try std.testing.expect(
                err ==
                    error.UnsupportedSingleFrameEscapeLength,
            );
        },

        .none,
        .event,
        => return error.TestUnexpectedResult,
    }
}
test "ISO-TP session exhaustion preserves active transfer and lineage" {
    const TestPipeline =
        Pipeline(
            2,
            1,
            64,
        );

    var pipeline: TestPipeline = .{};

    const first_data = [_]u8{
        0x10, 0x16,
        0x62, 0xf1,
        0x95, 0x00,
        0x02, 0x56,
    };

    const competing_first_data = [_]u8{
        0x10, 0x16,
        0x62, 0xf1,
        0x95, 0xaa,
        0xbb, 0xcc,
    };

    const consecutive_data = [_][8]u8{
        .{
            0x21, 0x00, 0x01, 0x52,
            0x15, 0x00, 0x00, 0x61,
        },
        .{
            0x22, 0x0a, 0x01, 0x0a,
            0x03, 0x0a, 0x0c, 0x00,
        },
        .{
            0x23, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        },
    };

    const first_frame =
        try can.FrameView.fromParts(
            0x18daf100,
            .extended,
            .data,
            first_data.len,
            &first_data,
        );

    const first_result =
        pipeline.push(
            .{ .index = 200 },
            first_frame,
        );

    try std.testing.expect(
        first_result.isotp == .none,
    );

    const competing_first_frame =
        try can.FrameView.fromParts(
            0x18daf101,
            .extended,
            .data,
            competing_first_data.len,
            &competing_first_data,
        );

    const competing_result =
        pipeline.push(
            .{ .index = 201 },
            competing_first_frame,
        );

    switch (competing_result.isotp) {
        .failure => |err| {
            try std.testing.expect(
                err == error.SessionCapacityExceeded,
            );
        },

        .none,
        .event,
        => return error.TestUnexpectedResult,
    }

    for (consecutive_data, 0..) |data, index| {
        const frame =
            try can.FrameView.fromParts(
                0x18daf100,
                .extended,
                .data,
                data.len,
                &data,
            );

        const result =
            pipeline.push(
                .{ .index = 202 + index },
                frame,
            );

        if (index < 2) {
            try std.testing.expect(
                result.isotp == .none,
            );

            continue;
        }

        switch (result.isotp) {
            .event => |event| {
                switch (event) {
                    .message => |completed| {
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
                            completed.message.payload,
                        );

                        try std.testing.expectEqual(
                            @as(usize, 4),
                            completed.lineage.len,
                        );

                        const expected_occurrences =
                            [_]usize{
                                200,
                                202,
                                203,
                                204,
                            };

                        for (
                            completed.lineage,
                            expected_occurrences,
                        ) |contribution, occurrence| {
                            try std.testing.expectEqual(
                                occurrence,
                                contribution
                                    .frame_occurrence.index,
                            );
                        }
                    },

                    else => return error.TestUnexpectedResult,
                }
            },

            .none,
            .failure,
            => return error.TestUnexpectedResult,
        }
    }
}

test "J1939 session exhaustion preserves active transfer and lineage" {
    const TestPipeline =
        Pipeline(
            1,
            2,
            64,
        );

    var pipeline: TestPipeline = .{};

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

    const packet_data = [_][8]u8{
        .{
            0x01,
            0x48,
            0x44,
            0x5a,
            0x2a,
            0x50,
            0x55,
            0x42,
        },
        .{
            0x02,
            0x4c,
            0x49,
            0x43,
            0x2d,
            0x44,
            0x45,
            0x4d,
        },
        .{
            0x03,
            0x4f,
            0x2a,
            0x53,
            0x59,
            0x4e,
            0x54,
            0x48,
        },
        .{
            0x04,
            0x30,
            0x30,
            0x30,
            0x31,
            0x2a,
            0x55,
            0x4e,
        },
        .{
            0x05,
            0x49,
            0x54,
            0x30,
            0x31,
            0x2a,
            0xff,
            0xff,
        },
    };

    const rts_frame =
        try can.FrameView.fromParts(
            0x1cecf900,
            .extended,
            .data,
            rts_data.len,
            &rts_data,
        );

    const start_result =
        pipeline.push(
            .{ .index = 300 },
            rts_frame,
        );

    try std.testing.expect(
        start_result.j1939 == .none,
    );

    const competing_rts_frame =
        try can.FrameView.fromParts(
            0x1cecf901,
            .extended,
            .data,
            rts_data.len,
            &rts_data,
        );

    const competing_result =
        pipeline.push(
            .{ .index = 301 },
            competing_rts_frame,
        );

    switch (competing_result.j1939) {
        .failure => |err| {
            try std.testing.expect(
                err == error.SessionCapacityExceeded,
            );
        },

        .none,
        .event,
        => return error.TestUnexpectedResult,
    }

    const cts_frame =
        try can.FrameView.fromParts(
            0x1cec00f9,
            .extended,
            .data,
            cts_data.len,
            &cts_data,
        );

    const cts_result =
        pipeline.push(
            .{ .index = 302 },
            cts_frame,
        );

    switch (cts_result.j1939) {
        .event => |event| {
            switch (event) {
                .unsupported_transport_control => {},
                else => return error.TestUnexpectedResult,
            }
        },

        .none,
        .failure,
        => return error.TestUnexpectedResult,
    }

    for (packet_data, 0..) |data, index| {
        const frame =
            try can.FrameView.fromParts(
                0x1cebf900,
                .extended,
                .data,
                data.len,
                &data,
            );

        const result =
            pipeline.push(
                .{ .index = 303 + index },
                frame,
            );

        if (index < 4) {
            try std.testing.expect(
                result.j1939 == .none,
            );

            continue;
        }

        switch (result.j1939) {
            .event => |event| {
                switch (event) {
                    .message => |completed| {
                        const expected = [_]u8{
                            0x48, 0x44, 0x5a, 0x2a,
                            0x50, 0x55, 0x42, 0x4c,
                            0x49, 0x43, 0x2d, 0x44,
                            0x45, 0x4d, 0x4f, 0x2a,
                            0x53, 0x59, 0x4e, 0x54,
                            0x48, 0x30, 0x30, 0x30,
                            0x31, 0x2a, 0x55, 0x4e,
                            0x49, 0x54, 0x30, 0x31,
                            0x2a,
                        };

                        try std.testing.expectEqualSlices(
                            u8,
                            &expected,
                            completed.message.data(),
                        );

                        try std.testing.expectEqual(
                            @as(usize, 5),
                            completed.lineage.len,
                        );

                        const expected_occurrences =
                            [_]usize{
                                303,
                                304,
                                305,
                                306,
                                307,
                            };

                        const expected_offsets =
                            [_]usize{
                                0,
                                7,
                                14,
                                21,
                                28,
                            };

                        const expected_lengths =
                            [_]usize{
                                7,
                                7,
                                7,
                                7,
                                5,
                            };

                        for (
                            completed.lineage,
                            expected_occurrences,
                            expected_offsets,
                            expected_lengths,
                        ) |
                            contribution,
                            occurrence,
                            offset,
                            byte_length,
                        | {
                            try std.testing.expectEqual(
                                occurrence,
                                contribution
                                    .frame_occurrence.index,
                            );

                            try std.testing.expectEqual(
                                offset,
                                contribution.message_offset,
                            );

                            try std.testing.expectEqual(
                                byte_length,
                                contribution.byte_length,
                            );
                        }
                    },

                    else => return error.TestUnexpectedResult,
                }
            },

            .none,
            .failure,
            => return error.TestUnexpectedResult,
        }
    }
}

test "single pass preserves J1939 and ISO-TP lineage from public demo" {
    const DemoPipeline =
        Pipeline(
            4,
            4,
            64,
        );

    var pipeline: DemoPipeline = .{};

    const lines = [_][]const u8{
        "1.000000,1,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,1cecf900,data:,10,21,00,05,ff,eb,fe,00,",
        "1.001000,2,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,1cec00f9,data:,11,05,01,ff,ff,eb,fe,00,",
        "1.002000,3,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,1cebf900,data:,01,48,44,5a,2a,50,55,42,",
        "1.003000,4,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,1cebf900,data:,02,4c,49,43,2d,44,45,4d,",
        "1.004000,5,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,1cebf900,data:,03,4f,2a,53,59,4e,54,48,",
        "1.005000,6,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,1cebf900,data:,04,30,30,30,31,2a,55,4e,",
        "1.006000,7,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,1cebf900,data:,05,49,54,30,31,2a,ff,ff,",
        "2.000000,8,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,10,24,62,f1,57,48,44,5a,",
        "2.001000,9,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18da00f1,data:,30,08,00,00,00,00,00,00,",
        "2.002000,10,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,21,2a,50,55,42,4c,49,43,",
        "2.003000,11,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,22,2d,44,45,4d,4f,2a,53,",
        "2.004000,12,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,23,59,4e,54,48,30,30,30,",
        "2.005000,13,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,24,31,2a,55,4e,49,54,30,",
        "2.006000,14,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,25,31,2a,00,00,00,00,00,",
    };

    var j1939_payload: [64]u8 = undefined;
    var j1939_payload_len: usize = 0;
    var found_j1939 = false;

    var isotp_payload: [64]u8 = undefined;
    var isotp_payload_len: usize = 0;
    var found_isotp = false;

    for (lines, 0..) |line, index| {
        const parsed =
            try ddec_csv.parseLine(
                line,
            );

        const record = switch (parsed) {
            .can => |record| record,
            else => return error.TestUnexpectedResult,
        };

        const frame =
            try record.frame();

        const result =
            pipeline.push(
                .{ .index = index },
                frame,
            );

        switch (result.j1939) {
            .none => {},

            .failure => |err| {
                return err;
            },

            .event => |event| {
                switch (event) {
                    .message => |completed| {
                        if (completed.message.pgn() ==
                            j1939.pgn_component_identification)
                        {
                            const payload =
                                completed.message.data();

                            @memcpy(
                                j1939_payload[0..payload.len],
                                payload,
                            );

                            j1939_payload_len =
                                payload.len;

                            found_j1939 = true;

                            try std.testing.expectEqual(
                                @as(usize, 5),
                                completed.lineage.len,
                            );

                            try std.testing.expectEqual(
                                @as(usize, 2),
                                completed.lineage[0]
                                    .frame_occurrence.index,
                            );

                            try std.testing.expectEqual(
                                @as(usize, 6),
                                completed.lineage[4]
                                    .frame_occurrence.index,
                            );
                        }
                    },

                    else => {},
                }
            },
        }

        switch (result.isotp) {
            .none => {},

            .failure => |err| {
                return err;
            },

            .event => |event| {
                switch (event) {
                    .message => |completed| {
                        const payload =
                            completed.message.payload;

                        if (payload.len >= 3 and
                            payload[0] == 0x62 and
                            payload[1] == 0xf1 and
                            payload[2] == 0x57)
                        {
                            @memcpy(
                                isotp_payload[0..payload.len],
                                payload,
                            );

                            isotp_payload_len =
                                payload.len;

                            found_isotp = true;

                            try std.testing.expectEqual(
                                @as(usize, 6),
                                completed.lineage.len,
                            );

                            try std.testing.expectEqual(
                                @as(usize, 7),
                                completed.lineage[0]
                                    .frame_occurrence.index,
                            );

                            try std.testing.expectEqual(
                                @as(usize, 9),
                                completed.lineage[1]
                                    .frame_occurrence.index,
                            );

                            try std.testing.expectEqual(
                                @as(usize, 13),
                                completed.lineage[5]
                                    .frame_occurrence.index,
                            );
                        }
                    },

                    else => {},
                }
            },
        }
    }

    try std.testing.expect(found_j1939);
    try std.testing.expect(found_isotp);

    try std.testing.expectEqual(
        @as(usize, 33),
        j1939_payload_len,
    );

    try std.testing.expectEqual(
        @as(usize, 36),
        isotp_payload_len,
    );

    try std.testing.expectEqualSlices(
        u8,
        j1939_payload[0..j1939_payload_len],
        isotp_payload[3..isotp_payload_len],
    );
}

test "rejected ISO-TP overlap preserves active transfer and lineage" {
    const TestPipeline =
        Pipeline(
            2,
            2,
            64,
        );

    var pipeline: TestPipeline = .{};

    const first_data = [_]u8{
        0x10, 0x16,
        0x62, 0xf1,
        0x95, 0x00,
        0x02, 0x56,
    };

    const overlapping_single_data = [_]u8{
        0x02, 0x10, 0x03,
        0x00, 0x00, 0x00,
        0x00, 0x00,
    };

    const consecutive_data = [_][8]u8{
        .{
            0x21, 0x00, 0x01, 0x52,
            0x15, 0x00, 0x00, 0x61,
        },
        .{
            0x22, 0x0a, 0x01, 0x0a,
            0x03, 0x0a, 0x0c, 0x00,
        },
        .{
            0x23, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        },
    };

    const first_frame =
        try can.FrameView.fromParts(
            0x18daf100,
            .extended,
            .data,
            first_data.len,
            &first_data,
        );

    const first_result =
        pipeline.push(
            .{ .index = 100 },
            first_frame,
        );

    try std.testing.expect(
        first_result.isotp == .none,
    );

    const overlapping_single_frame =
        try can.FrameView.fromParts(
            0x18daf100,
            .extended,
            .data,
            overlapping_single_data.len,
            &overlapping_single_data,
        );

    const overlap_result =
        pipeline.push(
            .{ .index = 101 },
            overlapping_single_frame,
        );

    switch (overlap_result.isotp) {
        .failure => |err| {
            try std.testing.expect(
                err == error.TransferAlreadyActive,
            );
        },

        .none,
        .event,
        => return error.TestUnexpectedResult,
    }

    for (consecutive_data, 0..) |data, index| {
        const frame =
            try can.FrameView.fromParts(
                0x18daf100,
                .extended,
                .data,
                data.len,
                &data,
            );

        const result =
            pipeline.push(
                .{ .index = 102 + index },
                frame,
            );

        if (index < 2) {
            try std.testing.expect(
                result.isotp == .none,
            );

            continue;
        }

        switch (result.isotp) {
            .event => |event| {
                switch (event) {
                    .message => |completed| {
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
                            completed.message.payload,
                        );

                        try std.testing.expectEqual(
                            @as(usize, 4),
                            completed.lineage.len,
                        );

                        const expected_occurrences =
                            [_]usize{
                                100,
                                102,
                                103,
                                104,
                            };

                        const expected_offsets =
                            [_]usize{
                                0,
                                6,
                                13,
                                20,
                            };

                        const expected_lengths =
                            [_]usize{
                                6,
                                7,
                                7,
                                2,
                            };

                        for (
                            completed.lineage,
                            expected_occurrences,
                            expected_offsets,
                            expected_lengths,
                        ) |
                            contribution,
                            occurrence,
                            offset,
                            byte_length,
                        | {
                            try std.testing.expectEqual(
                                occurrence,
                                contribution
                                    .frame_occurrence.index,
                            );

                            try std.testing.expectEqual(
                                offset,
                                contribution.message_offset,
                            );

                            try std.testing.expectEqual(
                                byte_length,
                                contribution.byte_length,
                            );
                        }
                    },

                    else => return error.TestUnexpectedResult,
                }
            },

            .none,
            .failure,
            => return error.TestUnexpectedResult,
        }
    }
}
