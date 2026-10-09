const std = @import("std");

pub const ParseError = error{
    MissingFieldDelimiter,
    TrailingData,
};

pub const ComponentIdentification = struct {
    make: []const u8,
    model: []const u8,
    serial_number: []const u8,
    unit_number: []const u8,
};

pub fn parse(
    payload: []const u8,
) ParseError!ComponentIdentification {
    var fields: [4][]const u8 = undefined;
    var field_index: usize = 0;
    var field_start: usize = 0;

    for (payload, 0..) |byte, index| {
        if (byte != '*') {
            continue;
        }

        if (field_index >= fields.len) {
            return error.TrailingData;
        }

        fields[field_index] =
            payload[field_start..index];

        field_index += 1;
        field_start = index + 1;
    }

    if (field_index != fields.len) {
        return error.MissingFieldDelimiter;
    }

    if (field_start != payload.len) {
        return error.TrailingData;
    }

    return .{
        .make = fields[0],
        .model = fields[1],
        .serial_number = fields[2],
        .unit_number = fields[3],
    };
}

test "decodes authentic component identification payload" {
    const payload = [_]u8{
        0x44, 0x54, 0x44, 0x53, 0x43, 0x2a, 0x34,
        0x37, 0x31, 0x4e, 0x31, 0x30, 0x2a, 0x53,
        0x30, 0x30, 0x36, 0x36, 0x39, 0x35, 0x31,
        0x2a, 0x36, 0x31, 0x31, 0x30, 0x33, 0x35,
        0x00, 0x00, 0x00, 0x00, 0x2a,
    };

    const component =
        try parse(&payload);

    try std.testing.expectEqualStrings(
        "DTDSC",
        component.make,
    );

    try std.testing.expectEqualStrings(
        "471N10",
        component.model,
    );

    try std.testing.expectEqualStrings(
        "S0066951",
        component.serial_number,
    );

    const expected_unit_number = [_]u8{
        '6',  '1',  '1',  '0',  '3', '5',
        0x00, 0x00, 0x00, 0x00,
    };

    try std.testing.expectEqualSlices(
        u8,
        &expected_unit_number,
        component.unit_number,
    );
}
