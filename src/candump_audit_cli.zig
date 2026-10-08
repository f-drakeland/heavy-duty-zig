const std = @import("std");
const Io = std.Io;
const candump_audit = @import("candump_audit.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    const args =
        try init.minimal.args.toSlice(arena);

    if (args.len != 2) {
        std.debug.print(
            "usage: candump_audit_cli <capture-file>\n",
            .{},
        );
        return;
    }

    const path = args[1];

    const text =
        try Io.Dir.cwd().readFileAlloc(
            io,
            path,
            arena,
            .limited(4 * 1024 * 1024),
        );

    const audit =
        candump_audit.auditText(text);

    std.debug.print(
        \\records seen: {}
        \\accepted: {}
        \\rejected: {}
        \\DLC 3: {}
        \\DLC 8: {}
        \\
    ,
        .{
            audit.records_seen,
            audit.accepted,
            audit.rejected,
            audit.dlc_3,
            audit.dlc_8,
        },
    );
}
