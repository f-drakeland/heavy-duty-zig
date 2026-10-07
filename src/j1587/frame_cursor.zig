const std = @import("std");

const j1708 = @import("../j1708.zig");
const decoder_module = @import("decoder.zig");
const observations = @import("observations.zig");
const parameters = @import("parameters.zig");

pub const Event = union(enum) {
    observation: observations.Observation,
    unsupported_parameter: decoder_module.UnsupportedParameter,
};

pub const CursorError =
    parameters.IteratorError ||
    decoder_module.DecodeError;

pub const FrameCursor = struct {
    iterator: parameters.Iterator,
    decoder: *decoder_module.Decoder,
    draining_observations: bool = false,

    pub fn init(
        frame: j1708.FrameView,
        decoder: *decoder_module.Decoder,
    ) parameters.IteratorError!FrameCursor {
        return .{
            .iterator = try parameters.Iterator.init(frame),
            .decoder = decoder,
        };
    }

    pub fn next(
        self: *FrameCursor,
    ) CursorError!?Event {
        while (true) {
            if (self.draining_observations) {
                if (try self.decoder.next()) |observation| {
                    return .{
                        .observation = observation,
                    };
                }

                self.draining_observations = false;
                continue;
            }

            const parameter =
                (try self.iterator.next()) orelse return null;

            const result =
                try self.decoder.pushParameter(parameter);

            switch (result) {
                .pending => {
                    continue;
                },

                .unsupported => |unsupported| {
                    return .{
                        .unsupported_parameter = unsupported,
                    };
                },

                .ready => {
                    self.draining_observations = true;
                },
            }
        }
    }
};

test "cursor exposes observations and unsupported parameters in frame order" {
    const raw = [_]u8{
        128,
        84,
        1,
        234,
        6,
        'S',
        'W',
        '-',
        '2',
        '.',
        '1',
        91,
        2,
        118,
    };

    const frame =
        try j1708.FrameView.fromDelimited(&raw);

    var decoder = decoder_module.Decoder.init();

    var cursor = try FrameCursor.init(
        frame,
        &decoder,
    );

    const first = (try cursor.next()).?;

    switch (first) {
        .unsupported_parameter => |unsupported| {
            try std.testing.expectEqual(
                @as(u16, 84),
                unsupported.pid,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    const second = (try cursor.next()).?;

    switch (second) {
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

    const third = (try cursor.next()).?;

    switch (third) {
        .unsupported_parameter => |unsupported| {
            try std.testing.expectEqual(
                @as(u16, 91),
                unsupported.pid,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(
        (try cursor.next()) == null,
    );
}

test "cursor preserves multisection state across J1708 frames" {
    const first_raw = [_]u8{
        128,
        192,
        6,
        234,
        0x10,
        6,
        'S',
        'W',
        '-',
        227,
    };

    const second_raw = [_]u8{
        128,
        192,
        5,
        234,
        0x11,
        '2',
        '.',
        '1',
        47,
    };

    const first_frame =
        try j1708.FrameView.fromDelimited(&first_raw);

    const second_frame =
        try j1708.FrameView.fromDelimited(&second_raw);

    var decoder = decoder_module.Decoder.init();

    var first_cursor = try FrameCursor.init(
        first_frame,
        &decoder,
    );

    // First PID 192 section is accepted, but produces no caller-visible event.
    try std.testing.expect(
        (try first_cursor.next()) == null,
    );

    var second_cursor = try FrameCursor.init(
        second_frame,
        &decoder,
    );

    const event = (try second_cursor.next()).?;

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
        (try second_cursor.next()) == null,
    );
}
