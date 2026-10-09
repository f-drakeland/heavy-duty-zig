const std = @import("std");
const can = @import("can.zig");

pub const Direction = enum {
    rx,
    tx,
};

pub const ParseError = error{
    InvalidRecord,
    InvalidTimestamp,
    InvalidChannel,
    InvalidDataLengthCode,
    InvalidIdentifierKind,
    InvalidIdentifier,
    InvalidDataMarker,
    InvalidDataByte,
    DataLengthMismatch,
};

pub const Record = struct {
    timestamp_text: []const u8,
    direction: Direction,
    channel: u8,
    identifier: u32,
    identifier_format: can.IdentifierFormat,
    data_length_code: u8,
    data_storage: [can.classic_data_max]u8,

    pub fn data(
        self: *const Record,
    ) []const u8 {
        return self.data_storage[0..self.data_length_code];
    }

    pub fn frame(
        self: *const Record,
    ) can.FrameError!can.FrameView {
        return can.FrameView.fromParts(
            self.identifier,
            self.identifier_format,
            .data,
            self.data_length_code,
            self.data(),
        );
    }
};

pub const Line = union(enum) {
    non_can,
    can: Record,
};

/// Parses one line of the DDEC CSV representation observed in the
/// authentic project corpus.
///
/// In this representation, `id:` denotes a standard CAN identifier and
/// `idx:` denotes an extended CAN identifier. The marker, rather than the
/// numeric identifier width, determines the CAN identifier format.
pub fn parseLine(
    line: []const u8,
) ParseError!Line {
    var fields =
        std.mem.splitScalar(u8, line, ',');

    const timestamp_text =
        fields.next() orelse
        return error.InvalidRecord;

    _ = fields.next() orelse
        return error.InvalidRecord;

    _ = fields.next() orelse
        return error.InvalidRecord;

    const event_type =
        fields.next() orelse
        return error.InvalidRecord;

    if (!std.mem.startsWith(
        u8,
        event_type,
        "CAN (",
    )) {
        return .non_can;
    }

    _ = std.fmt.parseFloat(
        f64,
        timestamp_text,
    ) catch {
        return error.InvalidTimestamp;
    };

    const direction_channel =
        fields.next() orelse
        return error.InvalidRecord;

    const direction: Direction =
        if (std.mem.startsWith(
            u8,
            direction_channel,
            "RX ch:",
        ))
            .rx
        else if (std.mem.startsWith(
            u8,
            direction_channel,
            "TX ch:",
        ))
            .tx
        else
            return error.InvalidChannel;

    const channel_text =
        direction_channel[6..];

    const channel =
        std.fmt.parseInt(
            u8,
            channel_text,
            10,
        ) catch {
            return error.InvalidChannel;
        };

    const dlc_field =
        fields.next() orelse
        return error.InvalidRecord;

    if (!std.mem.startsWith(
        u8,
        dlc_field,
        "Dlc:",
    )) {
        return error.InvalidDataLengthCode;
    }

    const data_length_code =
        std.fmt.parseInt(
            u8,
            dlc_field[4..],
            10,
        ) catch {
            return error.InvalidDataLengthCode;
        };

    if (data_length_code >
        can.classic_data_max)
    {
        return error.InvalidDataLengthCode;
    }

    const identifier_kind =
        fields.next() orelse
        return error.InvalidRecord;

    const identifier_format: can.IdentifierFormat =
        if (std.mem.eql(
            u8,
            identifier_kind,
            "id:",
        ))
            .standard
        else if (std.mem.eql(
            u8,
            identifier_kind,
            "idx:",
        ))
            .extended
        else
            return error.InvalidIdentifierKind;

    const identifier_text =
        fields.next() orelse
        return error.InvalidRecord;

    const identifier =
        std.fmt.parseInt(
            u32,
            identifier_text,
            16,
        ) catch {
            return error.InvalidIdentifier;
        };

    switch (identifier_format) {
        .standard => {
            if (identifier >
                can.standard_identifier_max)
            {
                return error.InvalidIdentifier;
            }
        },

        .extended => {
            if (identifier >
                can.extended_identifier_max)
            {
                return error.InvalidIdentifier;
            }
        },
    }

    const data_marker =
        fields.next() orelse
        return error.InvalidRecord;

    if (!std.mem.eql(
        u8,
        data_marker,
        "data:",
    )) {
        return error.InvalidDataMarker;
    }

    var data_storage: [can.classic_data_max]u8 =
        undefined;

    var index: usize = 0;

    while (index < data_length_code) : (index += 1) {
        const byte_text =
            fields.next() orelse
            return error.DataLengthMismatch;

        if (byte_text.len == 0) {
            return error.DataLengthMismatch;
        }

        if (byte_text.len != 2) {
            return error.InvalidDataByte;
        }

        data_storage[index] =
            std.fmt.parseInt(
                u8,
                byte_text,
                16,
            ) catch {
                return error.InvalidDataByte;
            };
    }

    while (fields.next()) |remaining| {
        if (std.mem.trim(
            u8,
            remaining,
            " \t\r",
        ).len != 0) {
            return error.DataLengthMismatch;
        }
    }

    return .{
        .can = .{
            .timestamp_text = timestamp_text,
            .direction = direction,
            .channel = channel,
            .identifier = identifier,
            .identifier_format = identifier_format,
            .data_length_code = data_length_code,
            .data_storage = data_storage,
        },
    };
}

test "parses authentic extended DDEC address claim record" {
    const line =
        "103.229833,972,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18eefff9,data:,00,00,01,00,00,00,00,00,";

    const parsed =
        try parseLine(line);

    switch (parsed) {
        .can => |record| {
            try std.testing.expectEqual(
                Direction.rx,
                record.direction,
            );

            try std.testing.expectEqual(
                @as(u8, 1),
                record.channel,
            );

            try std.testing.expectEqual(
                @as(u32, 0x18eefff9),
                record.identifier,
            );

            try std.testing.expectEqual(
                can.IdentifierFormat.extended,
                record.identifier_format,
            );

            const frame =
                try record.frame();

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{
                    0x00, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                },
                frame.data(),
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "parses authentic standard DDEC CAN record" {
    const line =
        "90.064136,480,On/Off,CAN (498),RX ch:1,Dlc:8,id:,308,data:,00,04,2f,e5,b6,a0,00,00,";

    const parsed =
        try parseLine(line);

    switch (parsed) {
        .can => |record| {
            try std.testing.expectEqual(
                @as(u32, 0x308),
                record.identifier,
            );

            try std.testing.expectEqual(
                can.IdentifierFormat.standard,
                record.identifier_format,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "low numeric idx identifier remains extended" {
    const line =
        "90.061915,90061915,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,303,data:,00,00,00,00,00,60,8c,01,";

    const parsed =
        try parseLine(line);

    switch (parsed) {
        .can => |record| {
            try std.testing.expectEqual(
                @as(u32, 0x303),
                record.identifier,
            );

            try std.testing.expectEqual(
                can.IdentifierFormat.extended,
                record.identifier_format,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "metadata line is preserved as non CAN" {
    const line =
        "0.000000,0,Single,Session Start (4484),ID:3667e881";

    const parsed =
        try parseLine(line);

    switch (parsed) {
        .non_can => {},
        else => return error.TestUnexpectedResult,
    }
}

test "rejects DDEC CAN record with missing payload byte" {
    const line =
        "103.229833,972,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18eefff9,data:,00,00,01,00,00,00,00,";

    try std.testing.expectError(
        error.DataLengthMismatch,
        parseLine(line),
    );
}
