const std = @import("std");

const capture_lineage = @import("capture_lineage.zig");
const j1939 = @import("j1939.zig");

/// Bounded capture-side lineage for active J1939 transport transfers.
///
/// J1939 assembly remains authoritative for transport membership and logical
/// payload ranges. This tracker only attaches capture frame occurrences to
/// those protocol-reported derivations.
pub fn J1939TransportLineageTracker(
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
            transfer: j1939.TransportTransfer = undefined,

            contributions: [contribution_capacity]capture_lineage.MessagePayloadContribution =
                undefined,

            contribution_count: usize = 0,
        };

        sessions: [session_capacity]Session =
            @splat(.{}),

        fn findSession(
            self: *Self,
            transfer: j1939.TransportTransfer,
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

        pub fn start(
            self: *Self,
            transfer: j1939.TransportTransfer,
        ) Error!void {
            if (self.findSession(transfer) != null) {
                return error.TransferAlreadyTracked;
            }

            const session =
                self.findFreeSession() orelse
                return error.SessionCapacityExceeded;

            session.* = .{
                .occupied = true,
                .transfer = transfer,
            };
        }

        pub fn recordPayload(
            self: *Self,
            frame_occurrence: capture_lineage.FrameOccurrenceId,
            derivation: j1939.TransportPayloadDerivation,
        ) Error!void {
            const session =
                self.findSession(
                    derivation.transfer,
                ) orelse
                return error.TransferNotTracked;

            if (session.contribution_count >=
                session.contributions.len)
            {
                return error.ContributionCapacityExceeded;
            }

            session.contributions[
                session.contribution_count
            ] = .{
                .frame_occurrence = frame_occurrence,
                .message_offset = derivation.contribution.offset,
                .byte_length = derivation.contribution.byte_length,
            };

            session.contribution_count += 1;
        }

        pub fn finish(
            self: *Self,
            transfer: j1939.TransportTransfer,
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

        pub fn abort(
            self: *Self,
            transfer: j1939.TransportTransfer,
        ) Error!void {
            const session =
                self.findSession(
                    transfer,
                ) orelse
                return error.TransferNotTracked;

            session.* = .{};
        }
    };
}

test "keeps interleaved J1939 transfer lineage isolated" {
    const Tracker =
        J1939TransportLineageTracker(2, 4);

    const transfer_a: j1939.TransportTransfer = .{
        .source_address = 0x00,
        .destination_address = 0xf9,
        .target_pgn = j1939.pgn_component_identification,
        .delivery = .rts_cts,
    };

    const transfer_b: j1939.TransportTransfer = .{
        .source_address = 0x31,
        .destination_address = 0xff,
        .target_pgn = j1939.pgn_diagnostic_message_1,
        .delivery = .bam,
    };

    var tracker: Tracker = .{};

    try tracker.start(transfer_a);
    try tracker.start(transfer_b);

    try tracker.recordPayload(
        .{ .index = 100 },
        .{
            .transfer = transfer_a,
            .contribution = .{
                .offset = 0,
                .byte_length = 7,
            },
        },
    );

    try tracker.recordPayload(
        .{ .index = 200 },
        .{
            .transfer = transfer_b,
            .contribution = .{
                .offset = 0,
                .byte_length = 7,
            },
        },
    );

    try tracker.recordPayload(
        .{ .index = 101 },
        .{
            .transfer = transfer_a,
            .contribution = .{
                .offset = 7,
                .byte_length = 7,
            },
        },
    );

    try tracker.recordPayload(
        .{ .index = 201 },
        .{
            .transfer = transfer_b,
            .contribution = .{
                .offset = 7,
                .byte_length = 3,
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
        @as(usize, 7),
        b[1].message_offset,
    );

    // Finishing B must not disturb the still-active A transfer.
    try tracker.recordPayload(
        .{ .index = 102 },
        .{
            .transfer = transfer_a,
            .contribution = .{
                .offset = 14,
                .byte_length = 5,
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
        @as(usize, 7),
        a[1].message_offset,
    );

    try std.testing.expectEqual(
        @as(usize, 102),
        a[2].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 14),
        a[2].message_offset,
    );
}

test "aborting one J1939 transfer leaves other lineage active" {
    const Tracker =
        J1939TransportLineageTracker(2, 4);

    const transfer_a: j1939.TransportTransfer = .{
        .source_address = 0x00,
        .destination_address = 0xf9,
        .target_pgn = j1939.pgn_component_identification,
        .delivery = .rts_cts,
    };

    const transfer_b: j1939.TransportTransfer = .{
        .source_address = 0x31,
        .destination_address = 0xff,
        .target_pgn = j1939.pgn_diagnostic_message_1,
        .delivery = .bam,
    };

    var tracker: Tracker = .{};

    try tracker.start(transfer_a);
    try tracker.start(transfer_b);

    try tracker.recordPayload(
        .{ .index = 300 },
        .{
            .transfer = transfer_a,
            .contribution = .{
                .offset = 0,
                .byte_length = 7,
            },
        },
    );

    try tracker.recordPayload(
        .{ .index = 400 },
        .{
            .transfer = transfer_b,
            .contribution = .{
                .offset = 0,
                .byte_length = 7,
            },
        },
    );

    try tracker.abort(transfer_a);

    try std.testing.expectError(
        error.TransferNotTracked,
        tracker.finish(transfer_a),
    );

    // Aborting A must not disturb B.
    try tracker.recordPayload(
        .{ .index = 401 },
        .{
            .transfer = transfer_b,
            .contribution = .{
                .offset = 7,
                .byte_length = 3,
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
        @as(usize, 400),
        b[0].frame_occurrence.index,
    );

    try std.testing.expectEqual(
        @as(usize, 401),
        b[1].frame_occurrence.index,
    );
}
