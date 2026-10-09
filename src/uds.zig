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

pub const ReadDataByIdentifierResponse = struct {
    data_identifier: u16,

    /// Every response byte following the leading DID.
    ///
    /// No DID-specific meaning or field boundaries are inferred here.
    data_after_identifier: []const u8,
};

pub const ReadDataByIdentifierParseError = error{
    TruncatedReadDataByIdentifierResponse,
};

/// Parses the leading DID from a positive ReadDataByIdentifier response.
///
/// This preserves structure only. It does not assign meaning to the DID or
/// interpret the bytes following it.
pub fn parseReadDataByIdentifierResponse(
    service: ServiceMessage,
) ReadDataByIdentifierParseError!?ReadDataByIdentifierResponse {
    if (service.service_id != 0x62) {
        return null;
    }

    if (service.data.len < 2) {
        return error.TruncatedReadDataByIdentifierResponse;
    }

    return .{
        .data_identifier = (@as(u16, service.data[0]) << 8) |
            @as(u16, service.data[1]),

        .data_after_identifier = service.data[2..],
    };
}

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

test "parses observed F157 read-data response structure" {
    const payload = [_]u8{
        0x62, 0xf1, 0x57,
        0x44, 0x54, 0x44,
        0x53, 0x43, 0x2a,
        0x34, 0x37, 0x31,
        0x4e, 0x31, 0x30,
        0x2a, 0x53, 0x30,
        0x30, 0x36, 0x36,
        0x39, 0x35, 0x31,
        0x2a, 0x36, 0x31,
        0x31, 0x30, 0x33,
        0x35, 0x00, 0x00,
        0x00, 0x00, 0x2a,
    };

    const message =
        try parse(&payload);

    const service = switch (message) {
        .service => |value| value,
        else => return error.TestUnexpectedResult,
    };

    const response =
        (try parseReadDataByIdentifierResponse(
            service,
        )) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(u16, 0xf157),
        response.data_identifier,
    );

    try std.testing.expectEqualSlices(
        u8,
        payload[3..],
        response.data_after_identifier,
    );
}

test "read-data response parser ignores other services" {
    const data = [_]u8{
        0x01, 0x00, 0x14,
    };

    const service: ServiceMessage = .{
        .service_id = 0x50,
        .positive_response_to = 0x10,
        .data = &data,
    };

    try std.testing.expect(
        try parseReadDataByIdentifierResponse(
            service,
        ) == null,
    );
}

test "read-data response parser rejects truncated DID" {
    const data = [_]u8{
        0xf1,
    };

    const service: ServiceMessage = .{
        .service_id = 0x62,
        .positive_response_to = 0x22,
        .data = &data,
    };

    try std.testing.expectError(
        error.TruncatedReadDataByIdentifierResponse,
        parseReadDataByIdentifierResponse(
            service,
        ),
    );
}
