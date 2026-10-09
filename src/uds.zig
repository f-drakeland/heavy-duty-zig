const std = @import("std");

pub const ParseError = error{
    EmptyMessage,
    TruncatedNegativeResponse,
};

pub const ServiceMessage = struct {
    service_id: u8,

    /// For a positive-response SID, this is the corresponding
    /// request SID. Otherwise null.
    positive_response_to: ?u8,

    data: []const u8,
};

pub const NegativeResponse = struct {
    request_service_id: u8,
    response_code: u8,

    /// Preserved trailing bytes, if present.
    data: []const u8,
};

pub const Message = union(enum) {
    service: ServiceMessage,
    negative_response: NegativeResponse,
};

/// Parses one reconstructed UDS application payload.
///
/// ISO-TP framing and addressing are handled by lower layers.
/// This parser preserves service-level evidence and does not
/// interpret service parameters such as DIDs or routine IDs.
pub fn parse(
    payload: []const u8,
) ParseError!Message {
    if (payload.len == 0) {
        return error.EmptyMessage;
    }

    const service_id = payload[0];

    if (service_id == 0x7f) {
        if (payload.len < 3) {
            return error.TruncatedNegativeResponse;
        }

        return .{
            .negative_response = .{
                .request_service_id = payload[1],
                .response_code = payload[2],
                .data = payload[3..],
            },
        };
    }

    return .{
        .service = .{
            .service_id = service_id,
            .positive_response_to = positiveResponseRequest(
                service_id,
            ),
            .data = payload[1..],
        },
    };
}

fn positiveResponseRequest(
    service_id: u8,
) ?u8 {
    if (service_id >= 0x40 and
        service_id <= 0x7e)
    {
        return service_id - 0x40;
    }

    return null;
}

test "parses authentic ReadDataByIdentifier request" {
    const payload = [_]u8{
        0x22,
        0xf1,
        0x00,
    };

    const message =
        try parse(&payload);

    switch (message) {
        .service => |service| {
            try std.testing.expectEqual(
                @as(u8, 0x22),
                service.service_id,
            );

            try std.testing.expectEqual(
                @as(?u8, null),
                service.positive_response_to,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{
                    0xf1,
                    0x00,
                },
                service.data,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "parses authentic positive ReadDataByIdentifier response" {
    const payload = [_]u8{
        0x62,
        0xf1,
        0x00,
        0x02,
        0x01,
        0x0a,
        0x03,
    };

    const message =
        try parse(&payload);

    switch (message) {
        .service => |service| {
            try std.testing.expectEqual(
                @as(u8, 0x62),
                service.service_id,
            );

            try std.testing.expectEqual(
                @as(?u8, 0x22),
                service.positive_response_to,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{
                    0xf1,
                    0x00,
                    0x02,
                    0x01,
                    0x0a,
                    0x03,
                },
                service.data,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "parses authentic negative response to service 22" {
    const payload = [_]u8{
        0x7f,
        0x22,
        0x78,
    };

    const message =
        try parse(&payload);

    switch (message) {
        .negative_response => |negative| {
            try std.testing.expectEqual(
                @as(u8, 0x22),
                negative.request_service_id,
            );

            try std.testing.expectEqual(
                @as(u8, 0x78),
                negative.response_code,
            );

            try std.testing.expectEqual(
                @as(usize, 0),
                negative.data.len,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "parses authentic negative response to service 31" {
    const payload = [_]u8{
        0x7f,
        0x31,
        0x78,
    };

    const message =
        try parse(&payload);

    switch (message) {
        .negative_response => |negative| {
            try std.testing.expectEqual(
                @as(u8, 0x31),
                negative.request_service_id,
            );

            try std.testing.expectEqual(
                @as(u8, 0x78),
                negative.response_code,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "preserves trailing negative-response data" {
    const payload = [_]u8{
        0x7f,
        0x22,
        0x78,
        0xaa,
        0xbb,
    };

    const message =
        try parse(&payload);

    switch (message) {
        .negative_response => |negative| {
            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{
                    0xaa,
                    0xbb,
                },
                negative.data,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "rejects truncated negative response" {
    const payload = [_]u8{
        0x7f,
        0x22,
    };

    try std.testing.expectError(
        error.TruncatedNegativeResponse,
        parse(&payload),
    );
}

test "rejects empty UDS message" {
    try std.testing.expectError(
        error.EmptyMessage,
        parse(&[_]u8{}),
    );
}
