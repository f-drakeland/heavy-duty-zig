const std = @import("std");

pub const dtc_data_length: usize = 4;

pub const ParseError = error{
    InvalidDtcLength,
    UnexpectedEmptyDtcSlot,
};

pub const DiagnosticTroubleCode = struct {
    spn: ?u32,
    fmi: u8,
    occurrence_count: u8,
    conversion_method: bool,
    raw: [dtc_data_length]u8,
};

pub const PayloadError = error{
    InvalidPayloadLength,
};

pub const LampStatus = enum(u2) {
    off = 0,
    on = 1,
    code_2 = 2,
    code_3 = 3,
};

pub const LampFlash = enum(u2) {
    slow = 0,
    fast = 1,
    code_2 = 2,
    code_3 = 3,
};

pub const LampStatuses = struct {
    malfunction_indicator: LampStatus,
    red_stop: LampStatus,
    amber_warning: LampStatus,
    protect: LampStatus,
};

pub const LampFlashes = struct {
    malfunction_indicator: LampFlash,
    red_stop: LampFlash,
    amber_warning: LampFlash,
    protect: LampFlash,
};

fn lampStatusFromBits(value: u8) LampStatus {
    return @fromBackingInt(@intCast(@as(u2, @truncate(value))));
}

fn lampFlashFromBits(value: u8) LampFlash {
    return @fromBackingInt(@intCast(@as(u2, @truncate(value))));
}

pub const PayloadView = struct {
    raw: []const u8,
    lamp_status_byte: u8,
    lamp_flash_byte: u8,
    dtc_data: []const u8,
    filler: []const u8,

    pub fn fromBytes(
        data: []const u8,
    ) PayloadError!PayloadView {
        if (data.len == 8) {
            return .{
                .raw = data,
                .lamp_status_byte = data[0],
                .lamp_flash_byte = data[1],
                .dtc_data = data[2..6],
                .filler = data[6..8],
            };
        }

        if (data.len < 10 or
            (data.len - 2) % dtc_data_length != 0)
        {
            return error.InvalidPayloadLength;
        }

        return .{
            .raw = data,
            .lamp_status_byte = data[0],
            .lamp_flash_byte = data[1],
            .dtc_data = data[2..],
            .filler = data[data.len..],
        };
    }

    pub fn dtcs(self: PayloadView) DtcIterator {
        return .{
            .remaining = self.dtc_data,
            .allow_empty_dtc = self.raw.len == 8,
        };
    }

    pub fn lampStatuses(self: PayloadView) LampStatuses {
        return .{
            .malfunction_indicator = lampStatusFromBits(self.lamp_status_byte >> 6),

            .red_stop = lampStatusFromBits(self.lamp_status_byte >> 4),

            .amber_warning = lampStatusFromBits(self.lamp_status_byte >> 2),

            .protect = lampStatusFromBits(self.lamp_status_byte),
        };
    }

    pub fn lampFlashes(self: PayloadView) LampFlashes {
        return .{
            .malfunction_indicator = lampFlashFromBits(self.lamp_flash_byte >> 6),

            .red_stop = lampFlashFromBits(self.lamp_flash_byte >> 4),

            .amber_warning = lampFlashFromBits(self.lamp_flash_byte >> 2),

            .protect = lampFlashFromBits(self.lamp_flash_byte),
        };
    }
};

pub const DtcIterator = struct {
    remaining: []const u8,
    allow_empty_dtc: bool,

    pub fn next(
        self: *DtcIterator,
    ) ParseError!?DiagnosticTroubleCode {
        while (self.remaining.len >= dtc_data_length) {
            const dtc_bytes =
                self.remaining[0..dtc_data_length];

            self.remaining =
                self.remaining[dtc_data_length..];

            if (std.mem.allEqual(u8, dtc_bytes, 0)) {
                if (self.allow_empty_dtc) {
                    self.allow_empty_dtc = false;
                    return null;
                }

                return error.UnexpectedEmptyDtcSlot;
            }

            self.allow_empty_dtc = false;

            return try parseDiagnosticTroubleCode(
                dtc_bytes,
            );
        }

        return null;
    }
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

test "views single-frame DM1 payload and preserves filler" {
    const data = [_]u8{
        0x00,
        0x55,
        0x45,
        0x23,
        0xa7,
        0x0c,
        0xff,
        0xff,
    };

    const payload =
        try PayloadView.fromBytes(&data);

    try std.testing.expectEqual(
        @as(u8, 0x00),
        payload.lamp_status_byte,
    );

    try std.testing.expectEqual(
        @as(u8, 0x55),
        payload.lamp_flash_byte,
    );

    try std.testing.expectEqualSlices(
        u8,
        data[2..6],
        payload.dtc_data,
    );

    try std.testing.expectEqualSlices(
        u8,
        data[6..8],
        payload.filler,
    );
}

test "DM1 DTC iterator ignores empty DTC slot" {
    const data = [_]u8{
        0x00,
        0x55,
        0x00,
        0x00,
        0x00,
        0x00,
        0xff,
        0xff,
    };

    const payload =
        try PayloadView.fromBytes(&data);

    var iterator = payload.dtcs();

    try std.testing.expect(
        try iterator.next() == null,
    );
}

test "DM1 DTC iterator returns populated DTC" {
    const data = [_]u8{
        0x00,
        0x55,
        0x45,
        0x23,
        0xa7,
        0x0c,
        0xff,
        0xff,
    };

    const payload =
        try PayloadView.fromBytes(&data);

    var iterator = payload.dtcs();

    const dtc = (try iterator.next()).?;

    try std.testing.expectEqual(
        @as(?u32, 0x52345),
        dtc.spn,
    );

    try std.testing.expect(
        try iterator.next() == null,
    );
}

test "DM1 DTC iterator returns multiple DTCs from logical payload" {
    const data = [_]u8{
        0x00,
        0x55,

        0x45,
        0x23,
        0xa7,
        0x0c,

        0x34,
        0x12,
        0x83,
        0x02,
    };

    const payload =
        try PayloadView.fromBytes(&data);

    var iterator = payload.dtcs();

    const first = (try iterator.next()).?;
    const second = (try iterator.next()).?;

    try std.testing.expectEqual(
        @as(?u32, 0x52345),
        first.spn,
    );

    try std.testing.expectEqual(
        @as(?u32, 0x41234),
        second.spn,
    );

    try std.testing.expectEqual(
        @as(u8, 3),
        second.fmi,
    );

    try std.testing.expectEqual(
        @as(u8, 2),
        second.occurrence_count,
    );

    try std.testing.expect(
        try iterator.next() == null,
    );
}

test "rejects empty DTC slot in multi-DTC logical payload" {
    const data = [_]u8{
        0x00,
        0x55,

        0x45,
        0x23,
        0xa7,
        0x0c,

        0x00,
        0x00,
        0x00,
        0x00,
    };

    const payload =
        try PayloadView.fromBytes(&data);

    var iterator = payload.dtcs();

    _ = (try iterator.next()).?;

    try std.testing.expectError(
        error.UnexpectedEmptyDtcSlot,
        iterator.next(),
    );
}

test "decodes DM1 lamp status and flash fields" {
    const data = [_]u8{
        0b01_00_01_11,
        0b00_01_10_11,
        0,
        0,
        0,
        0,
        0xff,
        0xff,
    };

    const payload =
        try PayloadView.fromBytes(&data);

    const statuses = payload.lampStatuses();
    const flashes = payload.lampFlashes();

    try std.testing.expectEqual(
        LampStatus.on,
        statuses.malfunction_indicator,
    );

    try std.testing.expectEqual(
        LampStatus.off,
        statuses.red_stop,
    );

    try std.testing.expectEqual(
        LampStatus.on,
        statuses.amber_warning,
    );

    try std.testing.expectEqual(
        LampStatus.code_3,
        statuses.protect,
    );

    try std.testing.expectEqual(
        LampFlash.slow,
        flashes.malfunction_indicator,
    );

    try std.testing.expectEqual(
        LampFlash.fast,
        flashes.red_stop,
    );

    try std.testing.expectEqual(
        LampFlash.code_2,
        flashes.amber_warning,
    );

    try std.testing.expectEqual(
        LampFlash.code_3,
        flashes.protect,
    );
}
