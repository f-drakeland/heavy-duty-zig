const std = @import("std");
const can = @import("can.zig");

pub const ParseError = error{
    InvalidRecord,
    InvalidTimestamp,
    InvalidIdentifier,
    InvalidDataLengthCode,
    InvalidDataByte,
    DataLengthMismatch,
};

pub const Record = struct {
    timestamp_text: []const u8,
    interface_name: []const u8,
    identifier: u32,
    data_length_code: u8,
    data_storage: [can.classic_data_max]u8,

    pub fn data(self: *const Record) []const u8 {
        return self.data_storage[0..self.data_length_code];
    }

    pub fn frame(self: *const Record) can.FrameError!can.FrameView {
        return can.FrameView.fromParts(
            self.identifier,
            .extended,
            .data,
            self.data_length_code,
            self.data(),
        );
    }
};

pub fn parseLine(
    line: []const u8,
) ParseError!Record {
    var tokens =
        std.mem.tokenizeAny(u8, line, " \t\r\n");

    const timestamp_token =
        tokens.next() orelse
        return error.InvalidRecord;

    if (timestamp_token.len < 3 or
        timestamp_token[0] != '(' or
        timestamp_token[timestamp_token.len - 1] != ')')
    {
        return error.InvalidTimestamp;
    }

    _ = std.fmt.parseFloat(
        f64,
        timestamp_token[1 .. timestamp_token.len - 1],
    ) catch {
        return error.InvalidTimestamp;
    };

    const interface_name =
        tokens.next() orelse
        return error.InvalidRecord;

    const identifier_token =
        tokens.next() orelse
        return error.InvalidRecord;

    // The authentic corpus uses eight hexadecimal digits for extended CAN IDs.
    if (identifier_token.len != 8) {
        return error.InvalidIdentifier;
    }

    const identifier =
        std.fmt.parseInt(
            u32,
            identifier_token,
            16,
        ) catch {
            return error.InvalidIdentifier;
        };

    if (identifier > can.extended_identifier_max) {
        return error.InvalidIdentifier;
    }

    const dlc_token =
        tokens.next() orelse
        return error.InvalidRecord;

    if (dlc_token.len < 3 or
        dlc_token[0] != '[' or
        dlc_token[dlc_token.len - 1] != ']')
    {
        return error.InvalidDataLengthCode;
    }

    const data_length_code =
        std.fmt.parseInt(
            u8,
            dlc_token[1 .. dlc_token.len - 1],
            10,
        ) catch {
            return error.InvalidDataLengthCode;
        };

    if (data_length_code > can.classic_data_max) {
        return error.InvalidDataLengthCode;
    }

    var data_storage: [can.classic_data_max]u8 =
        undefined;

    var index: usize = 0;

    while (index < data_length_code) : (index += 1) {
        const byte_token =
            tokens.next() orelse
            return error.DataLengthMismatch;

        if (byte_token.len != 2) {
            return error.InvalidDataByte;
        }

        data_storage[index] =
            std.fmt.parseInt(
                u8,
                byte_token,
                16,
            ) catch {
                return error.InvalidDataByte;
            };
    }

    if (tokens.next() != null) {
        return error.DataLengthMismatch;
    }

    return .{
        .timestamp_text = timestamp_token,
        .interface_name = interface_name,
        .identifier = identifier,
        .data_length_code = data_length_code,
        .data_storage = data_storage,
    };
}

test "parses eight-byte extended CAN record" {
    const line =
        "(012.345678) can1 18FECA80 [8] 00 55 45 23 A7 0C FF FF";

    const record =
        try parseLine(line);

    try std.testing.expectEqualStrings(
        "(012.345678)",
        record.timestamp_text,
    );

    try std.testing.expectEqualStrings(
        "can1",
        record.interface_name,
    );

    try std.testing.expectEqual(
        @as(u32, 0x18feca80),
        record.identifier,
    );

    try std.testing.expectEqual(
        @as(u8, 8),
        record.data_length_code,
    );

    const frame = try record.frame();

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{
            0x00,
            0x55,
            0x45,
            0x23,
            0xa7,
            0x0c,
            0xff,
            0xff,
        },
        frame.data(),
    );
}

test "parses three-byte extended CAN record" {
    const line =
        "(013.000001) can1 18EAFF80 [3] CA FE 00";

    const record =
        try parseLine(line);

    try std.testing.expectEqual(
        @as(u8, 3),
        record.data_length_code,
    );

    const frame = try record.frame();

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{
            0xca,
            0xfe,
            0x00,
        },
        frame.data(),
    );
}

test "rejects record with missing payload byte" {
    const line =
        "(012.345678) can1 18FECA80 [3] 00 55";

    try std.testing.expectError(
        error.DataLengthMismatch,
        parseLine(line),
    );
}

test "rejects record with extra payload byte" {
    const line =
        "(012.345678) can1 18FECA80 [3] 00 55 AA FF";

    try std.testing.expectError(
        error.DataLengthMismatch,
        parseLine(line),
    );
}

test "rejects malformed data byte" {
    const line =
        "(012.345678) can1 18FECA80 [3] 00 ZZ AA";

    try std.testing.expectError(
        error.InvalidDataByte,
        parseLine(line),
    );
}
