const std = @import("std");

const capture_audit = @import("capture_audit.zig");
const capture_text = @import("capture_text.zig");
const frame_recovery = @import("frame_recovery.zig");
const j1587 = @import("j1587.zig");

pub const UnhandledFrameReason = enum {
    not_j1587,
    unsupported_page,
    unsupported_parameter_layout,
};

pub const UnhandledFrame = struct {
    mid: u8,
    byte_length: usize,
    reason: UnhandledFrameReason,
};

pub const Event = union(enum) {
    j1587: j1587.frame_cursor.Event,
    unhandled_frame: UnhandledFrame,
};

pub const ProcessedEntry = struct {
    audit: capture_audit.Entry,
    cursor: ?RecordCursor,
};

pub const EventEntry = struct {
    line_number: usize,
    event: Event,
};

pub const Output = union(enum) {
    audit: capture_audit.Entry,
    event: EventEntry,
};

pub const PipelineError =
    frame_recovery.RecoveryError ||
    j1587.frame_cursor.CursorError;

const ActiveRecord = struct {
    line_number: usize,
    cursor: RecordCursor,
};

pub const RecordCursor = struct {
    frames: frame_recovery.RecoveredFrames,
    decoder: *j1587.Decoder,
    current_frame: ?j1587.frame_cursor.FrameCursor = null,

    pub fn next(
        self: *RecordCursor,
    ) j1587.frame_cursor.CursorError!?Event {
        while (true) {
            if (self.current_frame) |*cursor| {
                if (try cursor.next()) |event| {
                    return .{
                        .j1587 = event,
                    };
                }

                self.current_frame = null;
                continue;
            }

            const frame =
                self.frames.next() orelse return null;

            self.current_frame =
                j1587.frame_cursor.FrameCursor.init(
                    frame,
                    self.decoder,
                ) catch |err| switch (err) {
                    error.NotJ1587 => {
                        return .{
                            .unhandled_frame = .{
                                .mid = frame.mid(),
                                .byte_length = frame.bytes().len,
                                .reason = .not_j1587,
                            },
                        };
                    },

                    error.UnsupportedPage => {
                        return .{
                            .unhandled_frame = .{
                                .mid = frame.mid(),
                                .byte_length = frame.bytes().len,
                                .reason = .unsupported_page,
                            },
                        };
                    },

                    error.UnsupportedParameterLayout => {
                        return .{
                            .unhandled_frame = .{
                                .mid = frame.mid(),
                                .byte_length = frame.bytes().len,
                                .reason = .unsupported_parameter_layout,
                            },
                        };
                    },

                    else => return err,
                };
        }
    }
};

pub const CaptureCursor = struct {
    entries: capture_text.EntryIterator,
    scratch: []frame_recovery.ScratchState,
    decoder: *j1587.Decoder,

    current: ?ActiveRecord = null,
    summary_state: capture_audit.Summary = .{},

    pub fn init(
        input: []const u8,
        byte_storage: []u8,
        scratch: []frame_recovery.ScratchState,
        decoder: *j1587.Decoder,
    ) CaptureCursor {
        return .{
            .entries = capture_text.EntryIterator.init(
                input,
                byte_storage,
            ),
            .scratch = scratch,
            .decoder = decoder,
        };
    }

    pub fn next(
        self: *CaptureCursor,
    ) PipelineError!?Output {
        while (true) {
            // Always finish the current record before EntryIterator
            // is allowed to reuse its byte storage.
            if (self.current) |*active| {
                if (try active.cursor.next()) |event| {
                    return .{
                        .event = .{
                            .line_number = active.line_number,
                            .event = event,
                        },
                    };
                }

                self.current = null;
                continue;
            }

            const entry =
                self.entries.next() orelse return null;

            const processed = try processEntry(
                entry,
                self.scratch,
                self.decoder,
            );

            self.summary_state.observe(
                processed.audit,
            );

            const audit = processed.audit;

            if (processed.cursor) |cursor| {
                self.current = .{
                    .line_number = audit.line_number,
                    .cursor = cursor,
                };
            }

            // Every input record first produces its audit result.
            return .{
                .audit = audit,
            };
        }
    }

    pub fn summary(
        self: *const CaptureCursor,
    ) capture_audit.Summary {
        return self.summary_state;
    }
};

pub fn processEntry(
    entry: capture_text.Entry,
    scratch: []frame_recovery.ScratchState,
    decoder: *j1587.Decoder,
) frame_recovery.RecoveryError!ProcessedEntry {
    return switch (entry) {
        .rejected => |rejected| .{
            .audit = .{
                .line_number = rejected.line_number,
                .status = .rejected,
            },
            .cursor = null,
        },

        .record => |parsed| blk: {
            const recovery = try frame_recovery.recover(
                parsed.record.bytes,
                scratch,
            );

            break :blk switch (recovery) {
                .recovered => |frames| .{
                    .audit = .{
                        .line_number = parsed.line_number,
                        .status = .recovered,
                    },
                    .cursor = .{
                        .frames = frames,
                        .decoder = decoder,
                    },
                },

                .ambiguous => .{
                    .audit = .{
                        .line_number = parsed.line_number,
                        .status = .ambiguous,
                    },
                    .cursor = null,
                },

                .unrecoverable => .{
                    .audit = .{
                        .line_number = parsed.line_number,
                        .status = .unrecoverable,
                    },
                    .cursor = null,
                },
            };
        },
    };
}

test "processed capture record preserves audit and produces events" {
    const input =
        "STATUS_OK synthetic " ++
        "[128, 234, 6, 83, 87, 45, 50, 46, 49, 40]\n";

    var byte_storage: [64]u8 = undefined;
    var scratch: [65]frame_recovery.ScratchState = undefined;

    var entries = capture_text.EntryIterator.init(
        input,
        &byte_storage,
    );

    var decoder = j1587.Decoder.init();

    var processed = try processEntry(
        entries.next().?,
        &scratch,
        &decoder,
    );

    try std.testing.expectEqual(
        capture_audit.Status.recovered,
        processed.audit.status,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        processed.audit.line_number,
    );

    if (processed.cursor) |*cursor| {
        const event = (try cursor.next()).?;

        switch (event) {
            .j1587 => |j1587_event| {
                switch (j1587_event) {
                    .observation => |observation| {
                        switch (observation) {
                            .software_identification => |software| {
                                try std.testing.expectEqualSlices(
                                    u8,
                                    "SW-2.1",
                                    software.value,
                                );
                            },
                            else => return error.TestUnexpectedResult,
                        }
                    },

                    else => return error.TestUnexpectedResult,
                }
            },

            else => return error.TestUnexpectedResult,
        }

        try std.testing.expect(
            (try cursor.next()) == null,
        );
    } else {
        return error.TestUnexpectedResult;
    }
}

test "multisection state survives across capture records" {
    const input =
        "first [128, 192, 6, 234, 16, 6, 83, 87, 45, 227]\n" ++
        "second [128, 192, 5, 234, 17, 50, 46, 49, 47]\n";

    var byte_storage: [64]u8 = undefined;
    var scratch: [65]frame_recovery.ScratchState = undefined;

    var entries = capture_text.EntryIterator.init(
        input,
        &byte_storage,
    );

    var decoder = j1587.Decoder.init();

    // Record 1 contains PID 192 section 0/1.
    var first = try processEntry(
        entries.next().?,
        &scratch,
        &decoder,
    );

    try std.testing.expectEqual(
        capture_audit.Status.recovered,
        first.audit.status,
    );

    if (first.cursor) |*cursor| {
        // Reassembly is pending, so there is no caller-visible event yet.
        try std.testing.expect(
            (try cursor.next()) == null,
        );
    } else {
        return error.TestUnexpectedResult;
    }

    // Only after the first record is fully drained do we advance the
    // EntryIterator and allow it to reuse byte_storage.
    var second = try processEntry(
        entries.next().?,
        &scratch,
        &decoder,
    );

    try std.testing.expectEqual(
        capture_audit.Status.recovered,
        second.audit.status,
    );

    if (second.cursor) |*cursor| {
        const event = (try cursor.next()).?;

        switch (event) {
            .j1587 => |j1587_event| {
                switch (j1587_event) {
                    .observation => |observation| {
                        switch (observation) {
                            .software_identification => |software| {
                                try std.testing.expectEqualSlices(
                                    u8,
                                    "SW-2.1",
                                    software.value,
                                );
                            },
                            else => return error.TestUnexpectedResult,
                        }
                    },

                    else => return error.TestUnexpectedResult,
                }
            },

            else => return error.TestUnexpectedResult,
        }

        try std.testing.expect(
            (try cursor.next()) == null,
        );
    } else {
        return error.TestUnexpectedResult;
    }

    try std.testing.expect(
        entries.next() == null,
    );
}

test "capture cursor processes whole file in safe record order" {
    const input =
        "first [128, 192, 6, 234, 16, 6, 83, 87, 45, 227]\n" ++
        "bad [128, 999]\n" ++
        "second [128, 192, 5, 234, 17, 50, 46, 49, 47]\n";

    var byte_storage: [64]u8 = undefined;
    var scratch: [65]frame_recovery.ScratchState = undefined;
    var decoder = j1587.Decoder.init();

    var capture = CaptureCursor.init(
        input,
        &byte_storage,
        &scratch,
        &decoder,
    );

    // Record 1: recovered, but PID 192 remains pending.
    const first = (try capture.next()).?;

    switch (first) {
        .audit => |audit| {
            try std.testing.expectEqual(
                @as(usize, 1),
                audit.line_number,
            );

            try std.testing.expectEqual(
                capture_audit.Status.recovered,
                audit.status,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    // Record 1 is silently drained before record 2 is read.
    const second = (try capture.next()).?;

    switch (second) {
        .audit => |audit| {
            try std.testing.expectEqual(
                @as(usize, 2),
                audit.line_number,
            );

            try std.testing.expectEqual(
                capture_audit.Status.rejected,
                audit.status,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    // Record 3 completes the earlier PID 192 transfer.
    const third = (try capture.next()).?;

    switch (third) {
        .audit => |audit| {
            try std.testing.expectEqual(
                @as(usize, 3),
                audit.line_number,
            );

            try std.testing.expectEqual(
                capture_audit.Status.recovered,
                audit.status,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    const fourth = (try capture.next()).?;

    switch (fourth) {
        .event => |event_entry| {
            try std.testing.expectEqual(
                @as(usize, 3),
                event_entry.line_number,
            );

            switch (event_entry.event) {
                .j1587 => |j1587_event| {
                    switch (j1587_event) {
                        .observation => |observation| {
                            switch (observation) {
                                .software_identification => |software| {
                                    try std.testing.expectEqualSlices(
                                        u8,
                                        "SW-2.1",
                                        software.value,
                                    );
                                },
                                else => return error.TestUnexpectedResult,
                            }
                        },

                        else => return error.TestUnexpectedResult,
                    }
                },

                else => return error.TestUnexpectedResult,
            }
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(
        (try capture.next()) == null,
    );

    const summary = capture.summary();

    try std.testing.expectEqual(
        @as(usize, 3),
        summary.records,
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        summary.recovered,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        summary.rejected,
    );
}
