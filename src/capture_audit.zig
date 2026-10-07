const std = @import("std");

const capture_text = @import("capture_text.zig");
const frame_recovery = @import("frame_recovery.zig");

pub const Status = enum {
    recovered,
    ambiguous,
    unrecoverable,
    rejected,
};

pub const Entry = struct {
    line_number: usize,
    status: Status,
};

pub const Summary = struct {
    records: usize = 0,
    recovered: usize = 0,
    ambiguous: usize = 0,
    unrecoverable: usize = 0,
    rejected: usize = 0,

    pub fn observe(
        self: *Summary,
        entry: Entry,
    ) void {
        self.records += 1;

        switch (entry.status) {
            .recovered => self.recovered += 1,
            .ambiguous => self.ambiguous += 1,
            .unrecoverable => self.unrecoverable += 1,
            .rejected => self.rejected += 1,
        }
    }
};

pub fn classifyEntry(
    entry: capture_text.Entry,
    scratch: []frame_recovery.ScratchState,
) frame_recovery.RecoveryError!Entry {
    return switch (entry) {
        .rejected => |rejected| .{
            .line_number = rejected.line_number,
            .status = .rejected,
        },

        .record => |parsed| blk: {
            const result = try frame_recovery.recover(
                parsed.record.bytes,
                scratch,
            );

            break :blk .{
                .line_number = parsed.line_number,
                .status = switch (result) {
                    .recovered => .recovered,
                    .ambiguous => .ambiguous,
                    .unrecoverable => .unrecoverable,
                },
            };
        },
    };
}

test "audit classifies parsed and rejected capture lines" {
    const input =
        "good [128, 194, 0, 190]\n" ++
        "bad [128, 999]\n" ++
        "broken [1, 2, 3]\n";

    var byte_storage: [32]u8 = undefined;
    var scratch: [33]frame_recovery.ScratchState = undefined;

    var iterator = capture_text.EntryIterator.init(
        input,
        &byte_storage,
    );

    var summary = Summary{};

    const first = try classifyEntry(
        iterator.next().?,
        &scratch,
    );

    try std.testing.expectEqual(
        Status.recovered,
        first.status,
    );

    summary.observe(first);

    const second = try classifyEntry(
        iterator.next().?,
        &scratch,
    );

    try std.testing.expectEqual(
        Status.rejected,
        second.status,
    );

    summary.observe(second);

    const third = try classifyEntry(
        iterator.next().?,
        &scratch,
    );

    try std.testing.expectEqual(
        Status.unrecoverable,
        third.status,
    );

    summary.observe(third);

    try std.testing.expectEqual(
        @as(usize, 3),
        summary.records,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        summary.recovered,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        summary.rejected,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        summary.unrecoverable,
    );
}
