const std = @import("std");

pub const dtc_data_length: usize = 4;

pub const ParseError = error{
    InvalidDtcLength,
};

pub const DiagnosticTroubleCode = struct {
    spn: ?u32,
    fmi: u8,
    occurrence_count: u8,
    conversion_method: bool,
    raw: [dtc_data_length]u8,
};

pub fn parseDiagnosticTroubleCode(
    data: []const u8,
) ParseError!DiagnosticTroubleCode {
    if (data.len != dtc_data_length) {
        return error.InvalidDtcLength;
    }

    const conversion_method =
        (data[3] & 0x80) != 0;

    const spn =
        if (!conversion_method)
            @as(u32, data[0]) |
                (@as(u32, data[1]) << 8) |
                (@as(u32, data[2] & 0xe0) << 11)
        else
            null;

    return .{
        .spn = spn,
        .fmi = data[2] & 0x1f,
        .occurrence_count = data[3] & 0x7f,
        .conversion_method = conversion_method,
        .raw = .{
            data[0],
            data[1],
            data[2],
            data[3],
        },
    };
}

test "decodes version 4 diagnostic trouble code" {
    const data = [_]u8{
        0x45,
        0x23,
        0xa7,
        0x0c,
    };

    const dtc =
        try parseDiagnosticTroubleCode(&data);

    try std.testing.expectEqual(
        @as(?u32, 0x52345),
        dtc.spn,
    );

    try std.testing.expectEqual(
        @as(u8, 7),
        dtc.fmi,
    );

    try std.testing.expectEqual(
        @as(u8, 12),
        dtc.occurrence_count,
    );

    try std.testing.expect(
        !dtc.conversion_method,
    );

    try std.testing.expectEqualSlices(
        u8,
        &data,
        &dtc.raw,
    );
}

test "preserves DTC using unsupported conversion method" {
    const data = [_]u8{
        0x45,
        0x23,
        0xa7,
        0x8c,
    };

    const dtc =
        try parseDiagnosticTroubleCode(&data);

    try std.testing.expectEqual(
        @as(?u32, null),
        dtc.spn,
    );

    try std.testing.expectEqual(
        @as(u8, 7),
        dtc.fmi,
    );

    try std.testing.expectEqual(
        @as(u8, 12),
        dtc.occurrence_count,
    );

    try std.testing.expect(
        dtc.conversion_method,
    );

    try std.testing.expectEqualSlices(
        u8,
        &data,
        &dtc.raw,
    );
}

test "rejects incomplete diagnostic trouble code" {
    const data = [_]u8{
        0x45,
        0x23,
        0xa7,
    };

    try std.testing.expectError(
        error.InvalidDtcLength,
        parseDiagnosticTroubleCode(&data),
    );
}
