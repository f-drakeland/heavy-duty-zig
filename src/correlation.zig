const std = @import("std");

const j1587 = @import("j1587.zig");
const j1939 = @import("j1939.zig");

const can = @import("can.zig");
const capture_text = @import("capture_text.zig");
const frame_recovery = @import("frame_recovery.zig");

/// Identifies the protocol address from which evidence was observed.
///
/// This is capture-local network evidence. It is not a permanent ECU,
/// controller, component, or physical-device identity.
pub const EndpointKey = union(enum) {
    j1587_mid: u8,
    j1939_source_address: u8,

    pub fn eql(
        self: EndpointKey,
        other: EndpointKey,
    ) bool {
        return switch (self) {
            .j1587_mid => |mid| switch (other) {
                .j1587_mid => |other_mid| mid == other_mid,

                else => false,
            },

            .j1939_source_address => |source_address| switch (other) {
                .j1939_source_address => |other_source_address| source_address == other_source_address,

                else => false,
            },
        };
    }
};

/// Typed protocol evidence associated with an observed protocol endpoint.
///
/// Any slices contained in the underlying observation remain borrowed from
/// their original input storage. This type does not extend their lifetime.
pub const Evidence = union(enum) {
    j1587: j1587.Observation,
    j1939: j1939.Observation,
};

pub const EndpointObservation = struct {
    endpoint: EndpointKey,
    evidence: Evidence,
};

pub fn fromJ1587(
    observation: j1587.Observation,
) EndpointObservation {
    const source_mid = switch (observation) {
        .software_identification => |value| value.source_mid,

        .vin => |value| value.source_mid,

        .component_identification => |value| value.source_mid,

        .vehicle_distance => |value| value.source_mid,

        .road_speed => |value| value.source_mid,

        .accelerator_pedal_position => |value| value.source_mid,

        .engine_load => |value| value.source_mid,

        .engine_speed => |value| value.source_mid,

        .diagnostic_code => |value| value.source_mid,
    };

    return .{
        .endpoint = .{
            .j1587_mid = source_mid,
        },
        .evidence = .{
            .j1587 = observation,
        },
    };
}

pub fn fromJ1939(
    observation: j1939.Observation,
) EndpointObservation {
    const source_address = switch (observation) {
        .component_identification => |value| value.source_address,

        .address_claim => |value| value.source_address,

        .eec1_engine_speed => |value| value.source_address,

        .dm1_lamps => |value| value.source_address,

        .dm1_diagnostic_trouble_code => |value| value.source_address,
    };

    return .{
        .endpoint = .{
            .j1939_source_address = source_address,
        },
        .evidence = .{
            .j1939 = observation,
        },
    };
}

test "J1587 observation retains MID endpoint" {
    const observation: j1587.Observation = .{
        .engine_speed = .{
            .source_mid = 128,
            .raw_count = 2400,
            .rpm = 600.0,
        },
    };

    const correlated =
        fromJ1587(observation);

    switch (correlated.endpoint) {
        .j1587_mid => |mid| {
            try std.testing.expectEqual(
                @as(u8, 128),
                mid,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "J1939 observations from same source share endpoint key" {
    const engine_speed: j1939.Observation = .{
        .eec1_engine_speed = .{
            .source_address = 0x00,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    };

    const component: j1939.Observation = .{
        .component_identification = .{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "DTDSC",
            .model = "471N10",
            .serial_number = "S0066951",
            .unit_number = "611035",
        },
    };

    const first =
        fromJ1939(engine_speed);

    const second =
        fromJ1939(component);

    try std.testing.expect(
        first.endpoint.eql(second.endpoint),
    );
}

test "same numeric address across protocols is not same endpoint" {
    const j1587_endpoint: EndpointKey = .{
        .j1587_mid = 128,
    };

    const j1939_endpoint: EndpointKey = .{
        .j1939_source_address = 128,
    };

    try std.testing.expect(
        !j1587_endpoint.eql(j1939_endpoint),
    );
}

test "decoded J1587 observation becomes endpoint observation" {
    var byte_storage: [64]u8 = undefined;

    const record = try capture_text.parseLine(
        "STATUS_OK synthetic [128, 234, 6, 83, 87, 45, 50, 46, 49, 40]",
        &byte_storage,
    );

    var scratch: [65]frame_recovery.ScratchState = undefined;

    const recovery = try frame_recovery.recover(
        record.bytes,
        &scratch,
    );

    switch (recovery) {
        .recovered => |recovered_frames| {
            var frames = recovered_frames;

            const frame =
                frames.next() orelse
                return error.TestUnexpectedResult;

            var decoder = j1587.Decoder.init();

            var cursor =
                try j1587.frame_cursor.FrameCursor.init(
                    frame,
                    &decoder,
                );

            const event =
                (try cursor.next()).?;

            const observation = switch (event) {
                .observation => |observation| observation,

                else => return error.TestUnexpectedResult,
            };

            const endpoint_observation =
                fromJ1587(observation);

            switch (endpoint_observation.endpoint) {
                .j1587_mid => |mid| {
                    try std.testing.expectEqual(
                        @as(u8, 128),
                        mid,
                    );
                },

                else => return error.TestUnexpectedResult,
            }

            switch (endpoint_observation.evidence) {
                .j1587 => |evidence| {
                    switch (evidence) {
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
}

test "authentic J1939 address claim becomes endpoint observation" {
    const payload = [_]u8{
        0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    const can_frame =
        try can.FrameView.fromParts(
            0x18eefff9,
            .extended,
            .data,
            8,
            &payload,
        );

    const frame =
        try j1939.FrameView.fromCanFrame(
            can_frame,
        );

    const message =
        j1939.MessageView.fromSingleFrame(
            frame,
        );

    var cursor =
        try j1939.MessageCursor.init(
            message,
        );

    const event =
        (try cursor.next()).?;

    const observation = switch (event) {
        .observation => |observation| observation,

        else => return error.TestUnexpectedResult,
    };

    const endpoint_observation =
        fromJ1939(observation);

    switch (endpoint_observation.endpoint) {
        .j1939_source_address => |source_address| {
            try std.testing.expectEqual(
                @as(u8, 0xf9),
                source_address,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    switch (endpoint_observation.evidence) {
        .j1939 => |evidence| {
            switch (evidence) {
                .address_claim => |claim| {
                    try std.testing.expectEqual(
                        @as(u64, 0x0000000000010000),
                        claim.name.raw,
                    );

                    try std.testing.expectEqual(
                        @as(u32, 65536),
                        claim.name.identityNumber(),
                    );
                },

                else => return error.TestUnexpectedResult,
            }
        },

        else => return error.TestUnexpectedResult,
    }
}
