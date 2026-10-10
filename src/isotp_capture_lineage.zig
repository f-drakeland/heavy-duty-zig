const std = @import("std");

const capture_lineage = @import("capture_lineage.zig");
const isotp = @import("isotp.zig");

/// Bounded capture-side lineage for active ISO-TP transfers.
///
/// ISO-TP session routing and reassembly remain authoritative for transfer
/// membership and logical payload ranges. This tracker only attaches capture
/// frame occurrences to those protocol-reported derivations.
pub fn IsotpTransportLineageTracker(
    comptime session_capacity: usize,
    comptime contribution_capacity: usize,
) type {
    return struct {
        const Self = @This();

        pub const Error = error{
            SessionCapacityExceeded,
            TransferAlreadyTracked,
            TransferNotTracked,
            ContributionCapacityExceeded,
        };

        pub const CompletedLineage = struct {
            contributions: [contribution_capacity]capture_lineage.MessagePayloadContribution =
                undefined,

            contribution_count: usize = 0,

            pub fn slice(
                self: *const CompletedLineage,
            ) []const capture_lineage.MessagePayloadContribution {
                return self.contributions[0..self.contribution_count];
            }
        };

        const Session = struct {
            occupied: bool = false,
            transfer: isotp.RoutedTransfer = undefined,

            contributions: [contribution_capacity]capture_lineage.MessagePayloadContribution =
                undefined,

            contribution_count: usize = 0,
        };

        sessions: [session_capacity]Session =
            @splat(.{}),

        fn findSession(
            self: *Self,
            transfer: isotp.RoutedTransfer,
        ) ?*Session {
            for (&self.sessions) |*session| {
                if (session.occupied and
                    std.meta.eql(
                        session.transfer,
                        transfer,
                    ))
                {
                    return session;
                }
            }

            return null;
        }

        fn findFreeSession(
            self: *Self,
        ) ?*Session {
            for (&self.sessions) |*session| {
                if (!session.occupied) {
                    return session;
                }
            }

            return null;
        }

        fn appendContribution(
            session: *Session,
            frame_occurrence: capture_lineage.FrameOccurrenceId,
            contribution: isotp.PayloadContribution,
        ) Error!void {
            if (session.contribution_count >=
                session.contributions.len)
            {
                return error.ContributionCapacityExceeded;
            }

            session.contributions[
                session.contribution_count
            ] = .{
                .frame_occurrence = frame_occurrence,
                .message_offset = contribution.offset,
                .byte_length = contribution.byte_length,
            };

            session.contribution_count += 1;
        }

        pub fn start(
            self: *Self,
            frame_occurrence: capture_lineage.FrameOccurrenceId,
            derivation: isotp.RoutedPayloadContribution,
        ) Error!void {
            if (self.findSession(
                derivation.transfer,
            ) != null) {
                return error.TransferAlreadyTracked;
            }

            const session =
                self.findFreeSession() orelse
                return error.SessionCapacityExceeded;

            session.* = .{
                .occupied = true,
                .transfer = derivation.transfer,
            };

            try appendContribution(
                session,
                frame_occurrence,
                derivation.contribution,
            );
        }

        pub fn recordPayload(
            self: *Self,
            frame_occurrence: capture_lineage.FrameOccurrenceId,
            derivation: isotp.RoutedPayloadContribution,
        ) Error!void {
            const session =
                self.findSession(
                    derivation.transfer,
                ) orelse
                return error.TransferNotTracked;

            try appendContribution(
                session,
                frame_occurrence,
                derivation.contribution,
            );
        }

        pub fn finish(
            self: *Self,
            transfer: isotp.RoutedTransfer,
        ) Error!CompletedLineage {
            const session =
                self.findSession(
                    transfer,
                ) orelse
                return error.TransferNotTracked;

            var completed: CompletedLineage = .{
                .contribution_count = session.contribution_count,
            };

            @memcpy(
                completed.contributions[0..session.contribution_count],
                session.contributions[0..session.contribution_count],
            );

            session.* = .{};

            return completed;
        }
    };
}

test "keeps interleaved ISO-TP transfer lineage isolated" {
    const Tracker =
        IsotpTransportLineageTracker(2, 4);

    const transfer_a: isotp.RoutedTransfer = .{
        .source_address = 0x00,
        .destination_address = 0xf1,
        .delivery = .multi_frame,
    };

    const transfer_b: isotp.RoutedTransfer = .{
        .source_address = 0x31,
        .destination_address = 0xf9,
        .delivery = .multi_frame,
    };

    var tracker: Tracker = .{};

    try tracker.start(
        .{ .index = 100 },
        .{
            .transfer = transfer_a,
            .contribution = .{
                .offset = 0,
                .byte_length = 6,
            },
        },
    );

    try tracker.start(
        .{ .index = 200 },
        .{
            .transfer = transfer_b,
            .contribution = .{
                .offset = 0,
                .byte_length = 6,
            },
        },
    );

    try tracker.recordPayload(
        .{ .index = 101 },
        .{
            .transfer = transfer_a,
            .contribution = .{
                .offset = 6,
                .byte_length = 7,
            },
        },
    );

    try tracker.recordPayload(
        .{ .index = 201 },
        .{
            .transfer = transfer_b,
            .contribution = .{
                .offset = 6,
                .byte_length = 4,
            },
        },
    );

    const completed_b =
        try tracker.finish(transfer_b);

    const b =
        completed_b.slice();

    try std.testing.expectEqual(
        @as(usize, 2),
        b.len,
    );

    try std.testing.expectEqual(
        @as(usize, 200),
        b[0].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        b[0].message_offset,
    );

    try std.testing.expectEqual(
        @as(usize, 201),
        b[1].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 6),
        b[1].message_offset,
    );

    // Finishing B must not disturb the still-active A transfer.
    try tracker.recordPayload(
        .{ .index = 102 },
        .{
            .transfer = transfer_a,
            .contribution = .{
                .offset = 13,
                .byte_length = 3,
            },
        },
    );

    const completed_a =
        try tracker.finish(transfer_a);

    const a =
        completed_a.slice();

    try std.testing.expectEqual(
        @as(usize, 3),
        a.len,
    );

    try std.testing.expectEqual(
        @as(usize, 100),
        a[0].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        a[0].message_offset,
    );

    try std.testing.expectEqual(
        @as(usize, 101),
        a[1].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 6),
        a[1].message_offset,
    );

    try std.testing.expectEqual(
        @as(usize, 102),
        a[2].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 13),
        a[2].message_offset,
    );
}

test "router derivation keeps ISO-TP lineage synchronized across rejected frames" {
    const first_data = [_]u8{
        0x10, 0x09,
        0xaa, 0xbb,
        0xcc, 0xdd,
        0xee, 0xff,
    };

    const flow_control_data = [_]u8{
        0x30, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    const wrong_sequence_data = [_]u8{
        0x22,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
    };

    const correct_sequence_data = [_]u8{
        0x21,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
    };

    var router =
        isotp.SessionRouter(2, 64){};

    const Tracker =
        IsotpTransportLineageTracker(2, 64);

    var tracker: Tracker = .{};

    const first_result =
        try router.pushWithDerivation(
            0x00,
            0xf1,
            try isotp.parse(&first_data),
        );

    try std.testing.expect(
        first_result.event == .in_progress,
    );

    switch (first_result.derivation) {
        .transport_started => |derivation| {
            try tracker.start(
                .{ .index = 100 },
                derivation,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const flow_control_result =
        try router.pushWithDerivation(
            0xf1,
            0x00,
            try isotp.parse(&flow_control_data),
        );

    switch (flow_control_result.derivation) {
        .transport_context => |transfer| {
            try std.testing.expectEqual(
                @as(u8, 0x00),
                transfer.source_address,
            );

            try std.testing.expectEqual(
                @as(u8, 0xf1),
                transfer.destination_address,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    // The rejected frame must not advance either reassembly or lineage.
    try std.testing.expectError(
        error.UnexpectedSequenceNumber,
        router.pushWithDerivation(
            0x00,
            0xf1,
            try isotp.parse(&wrong_sequence_data),
        ),
    );

    const final_result =
        try router.pushWithDerivation(
            0x00,
            0xf1,
            try isotp.parse(&correct_sequence_data),
        );

    var completed_lineage: ?Tracker.CompletedLineage =
        null;

    switch (final_result.derivation) {
        .transport_payload => |derivation| {
            try tracker.recordPayload(
                .{ .index = 103 },
                derivation,
            );

            switch (final_result.event) {
                .completed => |message| {
                    try std.testing.expectEqualSlices(
                        u8,
                        &[_]u8{
                            0xaa, 0xbb, 0xcc,
                            0xdd, 0xee, 0xff,
                            0x01, 0x02, 0x03,
                        },
                        message.payload,
                    );

                    completed_lineage =
                        try tracker.finish(
                            derivation.transfer,
                        );
                },

                else => return error.TestUnexpectedResult,
            }
        },

        else => return error.TestUnexpectedResult,
    }

    const lineage =
        completed_lineage orelse
        return error.TestUnexpectedResult;

    const contributions =
        lineage.slice();

    try std.testing.expectEqual(
        @as(usize, 2),
        contributions.len,
    );

    try std.testing.expectEqual(
        @as(usize, 100),
        contributions[0].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        contributions[0].message_offset,
    );

    try std.testing.expectEqual(
        @as(usize, 6),
        contributions[0].byte_length,
    );

    try std.testing.expectEqual(
        @as(usize, 103),
        contributions[1].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 6),
        contributions[1].message_offset,
    );

    try std.testing.expectEqual(
        @as(usize, 3),
        contributions[1].byte_length,
    );
}
