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
