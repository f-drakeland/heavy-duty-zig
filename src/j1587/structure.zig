const std = @import("std");
const j1708 = @import("../j1708.zig");
const parameters = @import("parameters.zig");

pub const Inspection = enum {
    not_j1587,
    valid,
    invalid,
    unknown,
};

pub fn inspectFrame(frame: j1708.FrameView) Inspection {
    var iterator = parameters.Iterator.init(frame) catch |err| {
        return inspectionFromError(err);
    };

    while (true) {
        const parameter = iterator.next() catch |err| {
            return inspectionFromError(err);
        };

        if (parameter == null) return .valid;
    }
}

fn inspectionFromError(err: parameters.IteratorError) Inspection {
    return switch (err) {
        error.NotJ1587 => .not_j1587,

        error.MissingParameter,
        error.TruncatedParameter,
        error.MisplacedExtension,
        => .invalid,

        error.UnsupportedPage,
        error.UnsupportedParameterLayout,
        => .unknown,
    };
}

test "non-J1587 MID is not judged as J1587" {
    const raw = [_]u8{ 44, 212 };
    const frame = try j1708.FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(
        Inspection.not_j1587,
        inspectFrame(frame),
    );
}

test "multi-parameter J1587 frame is structurally valid" {
    const raw = [_]u8{
        128,
        84,
        1,
        91,
        2,
        92,
        3,
        190,
        4,
        5,
        168,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(
        Inspection.valid,
        inspectFrame(frame),
    );
}

test "variable-length J1587 parameter is structurally valid" {
    const raw = [_]u8{
        128,
        245,
        4,
        1,
        2,
        3,
        4,
        125,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(
        Inspection.valid,
        inspectFrame(frame),
    );
}

test "truncated fixed-length parameter is invalid" {
    const raw = [_]u8{ 128, 84, 44 };
    const frame = try j1708.FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(
        Inspection.invalid,
        inspectFrame(frame),
    );
}

test "truncated variable-length parameter is invalid" {
    const raw = [_]u8{ 128, 192, 3, 1, 2, 186 };
    const frame = try j1708.FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(
        Inspection.invalid,
        inspectFrame(frame),
    );
}

test "data-link escape consumes remaining bytes" {
    const raw = [_]u8{
        128, 254,
        171, 1,
        2,   212,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(
        Inspection.valid,
        inspectFrame(frame),
    );
}

test "extension PID after another parameter is invalid" {
    const raw = [_]u8{
        128,
        84,
        0,
        255,
        45,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(
        Inspection.invalid,
        inspectFrame(frame),
    );
}

test "unimplemented extension depth remains unknown" {
    const raw = [_]u8{
        128,
        255,
        255,
        255,
        255,
        0,
        1,
        131,
    };

    const frame = try j1708.FrameView.fromDelimited(&raw);

    try std.testing.expectEqual(
        Inspection.unknown,
        inspectFrame(frame),
    );
}
