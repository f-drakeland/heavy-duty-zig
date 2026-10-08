pub const can = @import("can.zig");
pub const j1939 = @import("j1939.zig");
pub const j1708 = @import("j1708.zig");
pub const j1587 = @import("j1587.zig");
pub const frame_recovery = @import("frame_recovery.zig");
pub const capture_text = @import("capture_text.zig");
pub const capture_audit = @import("capture_audit.zig");
pub const capture_pipeline = @import("capture_pipeline.zig");

test {
    _ = can;
    _ = j1939;
    _ = j1708;
    _ = j1587;
    _ = frame_recovery;
    _ = capture_text;
    _ = capture_audit;
    _ = capture_pipeline;
}

test "logger text reaches typed J1587 observation" {
    const std = @import("std");

    var byte_storage: [64]u8 = undefined;

    const record = try capture_text.parseLine(
        "STATUS_OK synthetic [128, 234, 6, 83, 87, 45, 50, 46, 49, 40]",
        &byte_storage,
    );

    var scratch: [65]frame_recovery.ScratchState = undefined;

    const result = try frame_recovery.recover(
        record.bytes,
        &scratch,
    );

    switch (result) {
        .recovered => |recovered_frames| {
            var frames = recovered_frames;

            const frame = frames.next().?;

            var decoder = j1587.Decoder.init();

            var cursor = try j1587.frame_cursor.FrameCursor.init(
                frame,
                &decoder,
            );

            const event = (try cursor.next()).?;

            switch (event) {
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

            try std.testing.expect(
                (try cursor.next()) == null,
            );

            try std.testing.expect(
                frames.next() == null,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}
