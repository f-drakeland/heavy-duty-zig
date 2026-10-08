const std = @import("std");

pub const standard_identifier_max: u32 = 0x7ff;
pub const extended_identifier_max: u32 = 0x1fffffff;
pub const classic_data_max: usize = 8;

pub const IdentifierFormat = enum {
    standard,
    extended,
};

pub const FrameKind = enum {
    data,
    remote,
};

pub const FrameError = error{
    IdentifierOutOfRange,
    DataLengthCodeOutOfRange,
    DataLengthMismatch,
    RemoteFrameHasData,
};

/// Borrowed view of one already-delimited classical CAN frame.
///
/// This type represents CAN framing only. It does not claim that an extended
/// identifier contains valid J1939 semantics.
pub const FrameView = struct {
    identifier_value: u32,
    identifier_format: IdentifierFormat,
    frame_kind: FrameKind,
    data_length_code: u8,
    data_bytes: []const u8,

    pub fn fromParts(
        identifier_value: u32,
        identifier_format: IdentifierFormat,
        frame_kind: FrameKind,
        data_length_code: u8,
        data_bytes: []const u8,
    ) FrameError!FrameView {
        switch (identifier_format) {
            .standard => {
                if (identifier_value > standard_identifier_max) {
                    return error.IdentifierOutOfRange;
                }
            },
            .extended => {
                if (identifier_value > extended_identifier_max) {
                    return error.IdentifierOutOfRange;
                }
            },
        }

        if (data_length_code > classic_data_max) {
            return error.DataLengthCodeOutOfRange;
        }

        switch (frame_kind) {
            .data => {
                if (data_bytes.len != @as(usize, data_length_code)) {
                    return error.DataLengthMismatch;
                }
            },
            .remote => {
                if (data_bytes.len != 0) {
                    return error.RemoteFrameHasData;
                }
            },
        }

        return .{
            .identifier_value = identifier_value,
            .identifier_format = identifier_format,
            .frame_kind = frame_kind,
            .data_length_code = data_length_code,
            .data_bytes = data_bytes,
        };
    }

    pub fn identifier(self: FrameView) u32 {
        return self.identifier_value;
    }

    pub fn format(self: FrameView) IdentifierFormat {
        return self.identifier_format;
    }

    pub fn kind(self: FrameView) FrameKind {
        return self.frame_kind;
    }

    pub fn dlc(self: FrameView) u8 {
        return self.data_length_code;
    }

    pub fn data(self: FrameView) []const u8 {
        return self.data_bytes;
    }
};

test "accepts extended classical CAN data frame" {
    const payload = [_]u8{
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
    };

    const frame = try FrameView.fromParts(
        0x18fef100,
        .extended,
        .data,
        8,
        &payload,
    );

    try std.testing.expectEqual(
        @as(u32, 0x18fef100),
        frame.identifier(),
    );

    try std.testing.expectEqual(
        IdentifierFormat.extended,
        frame.format(),
    );

    try std.testing.expectEqual(
        FrameKind.data,
        frame.kind(),
    );

    try std.testing.expectEqual(
        @as(u8, 8),
        frame.dlc(),
    );

    try std.testing.expectEqualSlices(
        u8,
        &payload,
        frame.data(),
    );
}

test "rejects standard identifier wider than 11 bits" {
    try std.testing.expectError(
        error.IdentifierOutOfRange,
        FrameView.fromParts(
            0x800,
            .standard,
            .data,
            0,
            &.{},
        ),
    );
}

test "rejects extended identifier wider than 29 bits" {
    try std.testing.expectError(
        error.IdentifierOutOfRange,
        FrameView.fromParts(
            0x20000000,
            .extended,
            .data,
            0,
            &.{},
        ),
    );
}

test "rejects classical CAN data length above eight bytes" {
    try std.testing.expectError(
        error.DataLengthCodeOutOfRange,
        FrameView.fromParts(
            0x18fef100,
            .extended,
            .data,
            9,
            &.{},
        ),
    );
}

test "data frame DLC must match borrowed data length" {
    const payload = [_]u8{ 0x01, 0x02 };

    try std.testing.expectError(
        error.DataLengthMismatch,
        FrameView.fromParts(
            0x18fef100,
            .extended,
            .data,
            1,
            &payload,
        ),
    );
}

test "remote frame may carry DLC but no data bytes" {
    const frame = try FrameView.fromParts(
        0x123,
        .standard,
        .remote,
        4,
        &.{},
    );

    try std.testing.expectEqual(
        @as(u8, 4),
        frame.dlc(),
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        frame.data().len,
    );
}

test "remote frame rejects data bytes" {
    const payload = [_]u8{0xaa};

    try std.testing.expectError(
        error.RemoteFrameHasData,
        FrameView.fromParts(
            0x123,
            .standard,
            .remote,
            1,
            &payload,
        ),
    );
}
