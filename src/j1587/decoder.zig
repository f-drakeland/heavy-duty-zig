const std = @import("std");

const multisection = @import("multisection.zig");
const observations_module = @import("observations.zig");
const parameters = @import("parameters.zig");
const parser = @import("parser.zig");

pub const DecodeError =
    multisection.ReassemblyError ||
    observations_module.DecodeError ||
    error{
        ObservationsPending,
    };

pub const UnsupportedParameter = struct {
    source_mid: u8,
    pid: u16,
    data_length: usize,
};

pub const PushResult = union(enum) {
    pending,
    ready,
    unsupported: UnsupportedParameter,
};

pub const Decoder = struct {
    multisection_bank: multisection.Bank,
    current_observations: ?observations_module.ObservationIterator = null,

    pub fn init() Decoder {
        return .{
            .multisection_bank = multisection.Bank.init(),
        };
    }

    pub fn push(
        self: *Decoder,
        raw_message: []const u8,
    ) DecodeError!PushResult {
        if (self.current_observations != null) {
            return error.ObservationsPending;
        }

        const message = try parser.parseMessage(raw_message);

        return self.pushParameterData(
            message.source_mid,
            message.pid,
            message.data,
        );
    }

    pub fn pushParameter(
        self: *Decoder,
        parameter: parameters.Parameter,
    ) DecodeError!PushResult {
        if (self.current_observations != null) {
            return error.ObservationsPending;
        }

        return self.pushParameterData(
            parameter.source_mid,
            parameter.pid,
            parameter.data,
        );
    }

    fn pushParameterData(
        self: *Decoder,
        source_mid: u8,
        pid: u16,
        data: []const u8,
    ) DecodeError!PushResult {
        if (pid == parser.pid_multisection) {
            const result = try self.multisection_bank.pushData(
                source_mid,
                data,
            );

            return switch (result) {
                .pending => .pending,
                .complete => |parameter| self.beginParameter(
                    parameter.source_mid,
                    parameter.pid,
                    parameter.data,
                ),
            };
        }

        return self.beginParameter(
            source_mid,
            pid,
            data,
        );
    }

    fn beginParameter(
        self: *Decoder,
        source_mid: u8,
        pid: u16,
        data: []const u8,
    ) DecodeError!PushResult {
        if (pid > 255) {
            return .{ .unsupported = .{
                .source_mid = source_mid,
                .pid = pid,
                .data_length = data.len,
            } };
        }

        const page_one_pid: u8 = @intCast(pid);

        if (!observations_module.supportsPid(page_one_pid)) {
            return .{ .unsupported = .{
                .source_mid = source_mid,
                .pid = pid,
                .data_length = data.len,
            } };
        }

        self.current_observations = observations_module.observations(
            source_mid,
            page_one_pid,
            data,
        );

        return .ready;
    }

    pub fn next(
        self: *Decoder,
    ) DecodeError!?observations_module.Observation {
        if (self.current_observations) |*iterator| {
            const observation = try iterator.next();

            if (observation == null) {
                self.current_observations = null;
            }

            return observation;
        }

        return null;
    }
};

test "new decoder has no observations" {
    var decoder = Decoder.init();

    try @import("std").testing.expectEqual(
        @as(?observations_module.Observation, null),
        try decoder.next(),
    );
}

test "ordinary PID 234 message produces observation" {
    var decoder = Decoder.init();

    const result = try decoder.push(
        "\x80\xea\x06SW-2.1",
    );

    try @import("std").testing.expectEqual(
        PushResult.ready,
        result,
    );

    const observation =
        (try decoder.next()) orelse
        return error.TestUnexpectedResult;

    switch (observation) {
        .software_identification => |software| {
            try @import("std").testing.expectEqual(
                @as(u8, 128),
                software.source_mid,
            );

            try @import("std").testing.expectEqualStrings(
                "SW-2.1",
                software.value,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try @import("std").testing.expectEqual(
        @as(?observations_module.Observation, null),
        try decoder.next(),
    );
}

test "multisection PID 243 produces component observation" {
    const first =
        "\x89\xc0\x11\xf3\x10\x18\x89DEMO *ABS-4S2";

    const second =
        "\x89\xc0\x0c\xf3\x11M*ABS-2099";

    var decoder = Decoder.init();

    try std.testing.expectEqual(
        PushResult.pending,
        try decoder.push(first),
    );

    try std.testing.expectEqual(
        PushResult.ready,
        try decoder.push(second),
    );

    const observation =
        (try decoder.next()) orelse
        return error.TestUnexpectedResult;

    switch (observation) {
        .component_identification => |component| {
            try std.testing.expectEqual(
                @as(u8, 137),
                component.source_mid,
            );

            try std.testing.expectEqual(
                @as(u8, 137),
                component.component_mid,
            );

            try std.testing.expectEqualStrings(
                "DEMO",
                component.manufacturer,
            );

            try std.testing.expectEqualStrings(
                "ABS-4S2M",
                component.model_name,
            );

            try std.testing.expectEqualStrings(
                "ABS-2099",
                component.serial,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(
        @as(?observations_module.Observation, null),
        try decoder.next(),
    );
}

test "reject new message while observations are pending" {
    var decoder = Decoder.init();

    try std.testing.expectEqual(
        PushResult.ready,
        try decoder.push("\x80\xea\x06SW-2.1"),
    );

    try std.testing.expectError(
        error.ObservationsPending,
        decoder.push("\x80\xea\x06SW-3.0"),
    );

    const observation =
        (try decoder.next()) orelse
        return error.TestUnexpectedResult;

    switch (observation) {
        .software_identification => |software| {
            try std.testing.expectEqualStrings(
                "SW-2.1",
                software.value,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    // Drain the iterator completely. This releases the current
    // observation state and permits another push.
    try std.testing.expectEqual(
        @as(?observations_module.Observation, null),
        try decoder.next(),
    );

    try std.testing.expectEqual(
        PushResult.ready,
        try decoder.push("\x80\xea\x06SW-3.0"),
    );
}

test "valid unsupported PID is reported without treating it as malformed" {
    var decoder = Decoder.init();

    const result = try decoder.push(
        "\x80\xc8\x02\xaa\xbb",
    );

    switch (result) {
        .unsupported => |parameter| {
            try std.testing.expectEqual(
                @as(u8, 128),
                parameter.source_mid,
            );

            try std.testing.expectEqual(
                @as(u8, 200),
                parameter.pid,
            );

            try std.testing.expectEqual(
                @as(usize, 2),
                parameter.data_length,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "unsupported multisection parameter is reported as metadata" {
    const first =
        "\x80\xc0\x05\xc8\x10\x04\xaa\xbb";

    const second =
        "\x80\xc0\x04\xc8\x11\xcc\xdd";

    var decoder = Decoder.init();

    try std.testing.expectEqual(
        PushResult.pending,
        try decoder.push(first),
    );

    const result = try decoder.push(second);

    switch (result) {
        .unsupported => |parameter| {
            try std.testing.expectEqual(
                @as(u8, 128),
                parameter.source_mid,
            );

            try std.testing.expectEqual(
                @as(u8, 200),
                parameter.pid,
            );

            try std.testing.expectEqual(
                @as(usize, 4),
                parameter.data_length,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "decoder accepts parsed J1587 parameter" {
    var decoder = Decoder.init();

    const parameter = parameters.Parameter{
        .source_mid = 128,
        .pid = 234,
        .data = "SW-2.1",
        .kind = .standard,
    };

    const result = try decoder.pushParameter(parameter);

    try std.testing.expect(result == .ready);

    const observation = (try decoder.next()).?;

    switch (observation) {
        .software_identification => |software| {
            try std.testing.expectEqual(@as(u8, 128), software.source_mid);
            try std.testing.expectEqualSlices(
                u8,
                "SW-2.1",
                software.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect((try decoder.next()) == null);
}

test "page-two parameter is valid but unsupported" {
    var decoder = Decoder.init();

    const parameter = parameters.Parameter{
        .source_mid = 128,
        .pid = 256,
        .data = &[_]u8{7},
        .kind = .standard,
    };

    const result = try decoder.pushParameter(parameter);

    switch (result) {
        .unsupported => |unsupported| {
            try std.testing.expectEqual(@as(u16, 256), unsupported.pid);
            try std.testing.expectEqual(@as(u8, 128), unsupported.source_mid);
            try std.testing.expectEqual(@as(usize, 1), unsupported.data_length);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "decoder consumes multiple parameters from one J1708 frame" {
    const j1708 = @import("../j1708.zig");

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

    const frame = try j1708.FrameView.fromDelimited(&raw);
    var iterator = try parameters.Iterator.init(frame);
    var decoder = Decoder.init();

    const first = (try iterator.next()).?;
    const first_result = try decoder.pushParameter(first);

    switch (first_result) {
        .unsupported => |unsupported| {
            try std.testing.expectEqual(@as(u16, 84), unsupported.pid);
        },
        else => return error.TestUnexpectedResult,
    }

    const second = (try iterator.next()).?;
    try std.testing.expect((try decoder.pushParameter(second)) == .ready);

    const observation = (try decoder.next()).?;

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

    // This null is important: it releases the decoder for the next parameter.
    try std.testing.expect((try decoder.next()) == null);

    const third = (try iterator.next()).?;
    const third_result = try decoder.pushParameter(third);

    switch (third_result) {
        .unsupported => |unsupported| {
            try std.testing.expectEqual(@as(u16, 91), unsupported.pid);
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect((try iterator.next()) == null);
}
