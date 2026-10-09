const std = @import("std");

pub const ParseError = error{
    InvalidLength,
};

pub const Name = struct {
    raw: u64,

    pub fn identityNumber(self: Name) u32 {
        return @intCast(self.raw & 0x1f_ffff);
    }

    pub fn manufacturerCode(self: Name) u16 {
        return @intCast((self.raw >> 21) & 0x7ff);
    }

    pub fn ecuInstance(self: Name) u8 {
        return @intCast((self.raw >> 32) & 0x07);
    }

    pub fn functionInstance(self: Name) u8 {
        return @intCast((self.raw >> 35) & 0x1f);
    }

    pub fn function(self: Name) u8 {
        return @intCast((self.raw >> 40) & 0xff);
    }

    pub fn reserved(self: Name) bool {
        return ((self.raw >> 48) & 0x01) != 0;
    }

    pub fn vehicleSystem(self: Name) u8 {
        return @intCast((self.raw >> 49) & 0x7f);
    }

    pub fn vehicleSystemInstance(self: Name) u8 {
        return @intCast((self.raw >> 56) & 0x0f);
    }

    pub fn industryGroup(self: Name) u8 {
        return @intCast((self.raw >> 60) & 0x07);
    }

    pub fn arbitraryAddressCapable(self: Name) bool {
        return ((self.raw >> 63) & 0x01) != 0;
    }
};

pub fn parse(payload: []const u8) ParseError!Name {
    if (payload.len != 8) {
        return error.InvalidLength;
    }

    const bytes: *const [8]u8 = payload[0..8];

    return .{
        .raw = std.mem.readInt(u64, bytes, .little),
    };
}

test "preserves authentic crash capture address claim NAME" {
    const name = try parse(&.{
        0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
    });

    try std.testing.expectEqual(
        @as(u64, 0x0000000000010000),
        name.raw,
    );

    try std.testing.expectEqual(
        @as(u32, 65536),
        name.identityNumber(),
    );
}

test "decodes address claim NAME fields" {
    const name = try parse(&.{
        0x64, 0x00, 0x40, 0x00,
        0x00, 0x03, 0x03, 0x10,
    });

    try std.testing.expectEqual(
        @as(u64, 0x1003030000400064),
        name.raw,
    );
    try std.testing.expectEqual(@as(u32, 100), name.identityNumber());
    try std.testing.expectEqual(@as(u16, 2), name.manufacturerCode());
    try std.testing.expectEqual(@as(u8, 0), name.ecuInstance());
    try std.testing.expectEqual(@as(u8, 0), name.functionInstance());
    try std.testing.expectEqual(@as(u8, 3), name.function());
    try std.testing.expect(name.reserved());
    try std.testing.expectEqual(@as(u8, 1), name.vehicleSystem());
    try std.testing.expectEqual(@as(u8, 0), name.vehicleSystemInstance());
    try std.testing.expectEqual(@as(u8, 1), name.industryGroup());
    try std.testing.expect(!name.arbitraryAddressCapable());
}

test "NAME keeps controller application distinctions" {
    const first = try parse(&.{
        0xf4, 0xb8, 0x4e, 0x01,
        0x00, 0x00, 0x00, 0x00,
    });

    const second = try parse(&.{
        0xf4, 0xb8, 0x4e, 0x01,
        0x00, 0x0c, 0x00, 0x00,
    });

    try std.testing.expectEqual(first.identityNumber(), second.identityNumber());
    try std.testing.expectEqual(first.manufacturerCode(), second.manufacturerCode());

    try std.testing.expectEqual(@as(u8, 0), first.function());
    try std.testing.expectEqual(@as(u8, 12), second.function());

    try std.testing.expect(first.raw != second.raw);
}
