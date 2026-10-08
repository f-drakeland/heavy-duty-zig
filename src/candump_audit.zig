const std = @import("std");
const candump = @import("candump.zig");

pub const Audit = struct {
    records_seen: usize = 0,
    accepted: usize = 0,
    rejected: usize = 0,
    dlc_3: usize = 0,
    dlc_8: usize = 0,
};

pub fn auditText(text: []const u8) Audit {
    var audit = Audit{};

    var lines =
        std.mem.splitScalar(u8, text, '\n');

    while (lines.next()) |line| {
        const trimmed =
            std.mem.trim(u8, line, " \t\r");

        if (trimmed.len == 0) {
            continue;
        }

        audit.records_seen += 1;

        const record =
            candump.parseLine(trimmed) catch {
                audit.rejected += 1;
                continue;
            };

        audit.accepted += 1;

        switch (record.data_length_code) {
            3 => audit.dlc_3 += 1,
            8 => audit.dlc_8 += 1,
            else => {},
        }
    }

    return audit;
}

test "audits accepted and rejected candump records" {
    const text =
        \\(001.000000) can1 18FECA80 [8] 00 55 45 23 A7 0C FF FF
        \\(002.000000) can1 18EAFF80 [3] CA FE 00
        \\this is not a candump record
    ;

    const audit =
        auditText(text);

    try std.testing.expectEqual(
        @as(usize, 3),
        audit.records_seen,
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        audit.accepted,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        audit.rejected,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        audit.dlc_3,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        audit.dlc_8,
    );
}
