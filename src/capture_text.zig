const std = @import("std");

pub const ParseError = error{
    MissingByteList,
    UnterminatedByteList,
    EmptyByteList,
    InvalidByte,
    StorageTooSmall,
};

pub const Record = struct {
    bytes: []const u8,
};

pub const Line = struct {
    number: usize,
    text: []const u8,
};

pub const LineIterator = struct {
    input: []const u8,
    cursor: usize = 0,
    line_number: usize = 0,

    pub fn init(input: []const u8) LineIterator {
        return .{
            .input = input,
        };
    }

    pub fn next(self: *LineIterator) ?Line {
        while (self.cursor < self.input.len) {
            const start = self.cursor;

            var end = start;
            while (end < self.input.len and
                self.input[end] != '\n') : (end += 1)
            {}

            self.cursor = if (end < self.input.len)
                end + 1
            else
                end;

            self.line_number += 1;

            var text = self.input[start..end];

            if (text.len > 0 and
                text[text.len - 1] == '\r')
            {
                text = text[0 .. text.len - 1];
            }

            if (std.mem.trim(
                u8,
                text,
                " \t",
            ).len == 0) {
                continue;
            }

            return .{
                .number = self.line_number,
                .text = text,
            };
        }

        return null;
    }
};

pub const ParsedLine = struct {
    line_number: usize,
    text: []const u8,
    record: Record,
};

pub const RejectedLine = struct {
    line_number: usize,
    text: []const u8,
    reason: ParseError,
};

pub const Entry = union(enum) {
    record: ParsedLine,
    rejected: RejectedLine,
};

pub const EntryIterator = struct {
    lines: LineIterator,
    storage: []u8,

    pub fn init(
        input: []const u8,
        storage: []u8,
    ) EntryIterator {
        return .{
            .lines = LineIterator.init(input),
            .storage = storage,
        };
    }

    /// Record bytes borrow `storage` and remain valid only until the next
    /// call to `next()`.
    pub fn next(self: *EntryIterator) ?Entry {
        const line = self.lines.next() orelse
            return null;

        const record = parseLine(
            line.text,
            self.storage,
        ) catch |err| {
            return .{
                .rejected = .{
                    .line_number = line.number,
                    .text = line.text,
                    .reason = err,
                },
            };
        };

        return .{
            .record = .{
                .line_number = line.number,
                .text = line.text,
                .record = record,
            },
        };
    }
};

pub fn parseLine(
    line: []const u8,
    storage: []u8,
) ParseError!Record {
    var open_index: ?usize = null;

    for (line, 0..) |byte, index| {
        if (byte == '[') {
            open_index = index;
            break;
        }
    }

    const open = open_index orelse
        return error.MissingByteList;

    var close_index: ?usize = null;
    var index = open + 1;

    while (index < line.len) : (index += 1) {
        if (line[index] == ']') {
            close_index = index;
            break;
        }
    }

    const close = close_index orelse
        return error.UnterminatedByteList;

    const body = line[open + 1 .. close];

    var tokens = std.mem.splitScalar(u8, body, ',');
    var count: usize = 0;

    while (tokens.next()) |raw_token| {
        const token = std.mem.trim(
            u8,
            raw_token,
            " \t\r\n",
        );

        if (token.len == 0) {
            return error.InvalidByte;
        }

        const value = std.fmt.parseInt(
            u8,
            token,
            10,
        ) catch return error.InvalidByte;

        if (count >= storage.len) {
            return error.StorageTooSmall;
        }

        storage[count] = value;
        count += 1;
    }

    if (count == 0) {
        return error.EmptyByteList;
    }

    return .{
        .bytes = storage[0..count],
    };
}

test "parses decimal byte list from logger-style line" {
    var storage: [32]u8 = undefined;

    const record = try parseLine(
        "STATUS_OK 18/08 11:59:17 SUM: 190  [128, 194, 0, 190]",
        &storage,
    );

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 128, 194, 0, 190 },
        record.bytes,
    );
}

test "rejects missing byte list" {
    var storage: [8]u8 = undefined;

    try std.testing.expectError(
        error.MissingByteList,
        parseLine("STATUS_OK no bytes here", &storage),
    );
}

test "rejects byte outside u8 range" {
    var storage: [8]u8 = undefined;

    try std.testing.expectError(
        error.InvalidByte,
        parseLine("[128, 256]", &storage),
    );
}

test "reports insufficient caller storage" {
    var storage: [3]u8 = undefined;

    try std.testing.expectError(
        error.StorageTooSmall,
        parseLine("[128, 194, 0, 190]", &storage),
    );
}

test "line iterator walks capture text with line numbers" {
    const input =
        "first [128, 128]\n" ++
        "second [128, 194, 0, 190]\n";

    var iterator = LineIterator.init(input);

    const first = iterator.next().?;
    try std.testing.expectEqual(
        @as(usize, 1),
        first.number,
    );
    try std.testing.expectEqualSlices(
        u8,
        "first [128, 128]",
        first.text,
    );

    const second = iterator.next().?;
    try std.testing.expectEqual(
        @as(usize, 2),
        second.number,
    );
    try std.testing.expectEqualSlices(
        u8,
        "second [128, 194, 0, 190]",
        second.text,
    );

    try std.testing.expect(
        iterator.next() == null,
    );
}

test "line iterator handles CRLF and skips blank lines" {
    const input =
        "first [128, 128]\r\n" ++
        "\r\n" ++
        "second [128, 194, 0, 190]\r\n";

    var iterator = LineIterator.init(input);

    const first = iterator.next().?;
    try std.testing.expectEqual(
        @as(usize, 1),
        first.number,
    );

    const second = iterator.next().?;
    try std.testing.expectEqual(
        @as(usize, 3),
        second.number,
    );

    try std.testing.expect(
        iterator.next() == null,
    );
}

test "entry iterator continues after malformed capture line" {
    const input =
        "first [128, 128]\n" ++
        "bad [128, 999]\n" ++
        "third [128, 194, 0, 190]\n";

    var storage: [32]u8 = undefined;

    var iterator = EntryIterator.init(
        input,
        &storage,
    );

    const first = iterator.next().?;

    switch (first) {
        .record => |parsed| {
            try std.testing.expectEqual(
                @as(usize, 1),
                parsed.line_number,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{ 128, 128 },
                parsed.record.bytes,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    const second = iterator.next().?;

    switch (second) {
        .rejected => |rejected| {
            try std.testing.expectEqual(
                @as(usize, 2),
                rejected.line_number,
            );

            try std.testing.expect(
                rejected.reason == error.InvalidByte,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    const third = iterator.next().?;

    switch (third) {
        .record => |parsed| {
            try std.testing.expectEqual(
                @as(usize, 3),
                parsed.line_number,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{ 128, 194, 0, 190 },
                parsed.record.bytes,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(
        iterator.next() == null,
    );
}
