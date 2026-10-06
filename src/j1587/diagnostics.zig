const std = @import("std");

pub const IdentifierKind = enum {
    pid,
    sid,
};

pub const FaultStatus = enum {
    active,
    inactive,
};

pub const DiagnosticCode = struct {
    source_mid: u8,
    identifier_kind: IdentifierKind,
    identifier: u16,
    fmi: u8,
    status: FaultStatus,
    occurrence_count: ?u8,
};

pub const DecodeError = error{
    TruncatedEntry,
    MissingOccurrenceCount,
};

pub const DiagnosticCodeIterator = struct {
    source_mid: u8,
    data: []const u8,
    index: usize = 0,

    pub fn next(
        self: *DiagnosticCodeIterator,
    ) DecodeError!?DiagnosticCode {
        if (self.index == self.data.len) {
            return null;
        }

        if (self.data.len - self.index < 2) {
            return error.TruncatedEntry;
        }

        const raw_identifier = self.data[self.index];
        const flags = self.data[self.index + 1];

        self.index += 2;

        const has_occurrence_count =
            (flags & 0x80) != 0;

        const status: FaultStatus =
            if ((flags & 0x40) != 0)
                .inactive
            else
                .active;

        const page_one =
            (flags & 0x20) != 0;

        const identifier_kind: IdentifierKind =
            if ((flags & 0x10) != 0)
                .sid
            else
                .pid;

        const page_offset: u16 =
            if (page_one) 0 else 256;

        const identifier: u16 =
            @as(u16, raw_identifier) + page_offset;

        const fmi =
            flags & 0x0f;

        var occurrence_count: ?u8 = null;

        if (has_occurrence_count) {
            if (self.index >= self.data.len) {
                return error.MissingOccurrenceCount;
            }

            occurrence_count = self.data[self.index];
            self.index += 1;
        }

        return .{
            .source_mid = self.source_mid,
            .identifier_kind = identifier_kind,
            .identifier = identifier,
            .fmi = fmi,
            .status = status,
            .occurrence_count = occurrence_count,
        };
    }
};

pub fn diagnosticCodes(
    source_mid: u8,
    data: []const u8,
) DiagnosticCodeIterator {
    return .{
        .source_mid = source_mid,
        .data = data,
    };
}

test "decode active PID diagnostic code" {
    var codes = diagnosticCodes(
        128,
        "\x6e\x20",
    );

    const code =
        (try codes.next()) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(u8, 128),
        code.source_mid,
    );

    try std.testing.expectEqual(
        IdentifierKind.pid,
        code.identifier_kind,
    );

    try std.testing.expectEqual(
        @as(u16, 110),
        code.identifier,
    );

    try std.testing.expectEqual(
        @as(u8, 0),
        code.fmi,
    );

    try std.testing.expectEqual(
        FaultStatus.active,
        code.status,
    );

    try std.testing.expectEqual(
        @as(?u8, null),
        code.occurrence_count,
    );

    try std.testing.expectEqual(
        @as(?DiagnosticCode, null),
        try codes.next(),
    );
}

test "decode inactive SID diagnostic code" {
    var codes = diagnosticCodes(
        128,
        "\x15\x72",
    );

    const code =
        (try codes.next()) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(u8, 128),
        code.source_mid,
    );

    try std.testing.expectEqual(
        IdentifierKind.sid,
        code.identifier_kind,
    );

    try std.testing.expectEqual(
        @as(u16, 21),
        code.identifier,
    );

    try std.testing.expectEqual(
        @as(u8, 2),
        code.fmi,
    );

    try std.testing.expectEqual(
        FaultStatus.inactive,
        code.status,
    );

    try std.testing.expectEqual(
        @as(?u8, null),
        code.occurrence_count,
    );

    try std.testing.expectEqual(
        @as(?DiagnosticCode, null),
        try codes.next(),
    );
}

test "decode diagnostic code with occurrence count" {
    var codes = diagnosticCodes(
        128,
        "\x6c\xa8\x01",
    );

    const code =
        (try codes.next()) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        IdentifierKind.pid,
        code.identifier_kind,
    );

    try std.testing.expectEqual(
        @as(u16, 108),
        code.identifier,
    );

    try std.testing.expectEqual(
        @as(u8, 8),
        code.fmi,
    );

    try std.testing.expectEqual(
        FaultStatus.active,
        code.status,
    );

    try std.testing.expectEqual(
        @as(?u8, 1),
        code.occurrence_count,
    );

    try std.testing.expectEqual(
        @as(?DiagnosticCode, null),
        try codes.next(),
    );
}

test "reject diagnostic code missing occurrence count byte" {
    var codes = diagnosticCodes(
        128,
        "\x6c\xa8",
    );

    try std.testing.expectError(
        error.MissingOccurrenceCount,
        codes.next(),
    );
}

test "decode multiple diagnostic codes from one table" {
    var codes = diagnosticCodes(
        128,
        "\x6e\x20" ++
            "\x15\x72" ++
            "\x6c\xa8\x01",
    );

    const first =
        (try codes.next()) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        IdentifierKind.pid,
        first.identifier_kind,
    );
    try std.testing.expectEqual(
        @as(u16, 110),
        first.identifier,
    );
    try std.testing.expectEqual(
        @as(u8, 0),
        first.fmi,
    );
    try std.testing.expectEqual(
        FaultStatus.active,
        first.status,
    );
    try std.testing.expectEqual(
        @as(?u8, null),
        first.occurrence_count,
    );

    const second =
        (try codes.next()) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        IdentifierKind.sid,
        second.identifier_kind,
    );
    try std.testing.expectEqual(
        @as(u16, 21),
        second.identifier,
    );
    try std.testing.expectEqual(
        @as(u8, 2),
        second.fmi,
    );
    try std.testing.expectEqual(
        FaultStatus.inactive,
        second.status,
    );

    const third =
        (try codes.next()) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        IdentifierKind.pid,
        third.identifier_kind,
    );
    try std.testing.expectEqual(
        @as(u16, 108),
        third.identifier,
    );
    try std.testing.expectEqual(
        @as(u8, 8),
        third.fmi,
    );
    try std.testing.expectEqual(
        FaultStatus.active,
        third.status,
    );
    try std.testing.expectEqual(
        @as(?u8, 1),
        third.occurrence_count,
    );

    try std.testing.expectEqual(
        @as(?DiagnosticCode, null),
        try codes.next(),
    );
}

test "empty diagnostic table contains no codes" {
    var codes = diagnosticCodes(
        128,
        "",
    );

    try std.testing.expectEqual(
        @as(?DiagnosticCode, null),
        try codes.next(),
    );
}

test "decode page-two diagnostic identifier" {
    var codes = diagnosticCodes(
        128,
        "\x05\x01",
    );

    const code =
        (try codes.next()) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        IdentifierKind.pid,
        code.identifier_kind,
    );

    try std.testing.expectEqual(
        @as(u16, 261),
        code.identifier,
    );

    try std.testing.expectEqual(
        @as(u8, 1),
        code.fmi,
    );

    try std.testing.expectEqual(
        FaultStatus.active,
        code.status,
    );

    try std.testing.expectEqual(
        @as(?u8, null),
        code.occurrence_count,
    );
}
