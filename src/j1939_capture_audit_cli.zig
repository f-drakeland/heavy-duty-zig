const std = @import("std");
const Io = std.Io;
const j1939 = @import("j1939.zig");
const capture_audit = @import("j1939_capture_audit.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    const args =
        try init.minimal.args.toSlice(arena);

    if (args.len != 2) {
        std.debug.print(
            "usage: j1939_capture_audit_cli <capture-file>\n",
            .{},
        );
        return;
    }

    const text =
        try Io.Dir.cwd().readFileAlloc(
            io,
            args[1],
            arena,
            .limited(4 * 1024 * 1024),
        );

    const audit =
        capture_audit.auditText(
            j1939.transport.reassembly.maximum_message_size,
            4,
            text,
        );

    std.debug.print(
        \\records seen: {}
        \\records parsed: {}
        \\parse rejected: {}
        \\J1939 frames: {}
        \\J1939 rejected: {}
        \\TP.CM frames: {}
        \\TP.DT frames: {}
        \\direct DM1 frames: {}
        \\single-frame messages: {}
        \\BAM started: {}
        \\BAM completed: {}
        \\unsupported transport controls: {}
        \\assembly errors: {}
        \\EEC1 engine speed observations: {}
        \\DM1 lamp observations: {}
        \\DM1 DTC observations: {}
        \\unsupported PGN messages: {}
        \\decode errors: {}
        \\
    ,
        .{
            audit.records_seen,
            audit.records_parsed,
            audit.parse_rejected,
            audit.j1939_frames,
            audit.j1939_rejected,
            audit.tp_cm_frames,
            audit.tp_dt_frames,
            audit.direct_dm1_frames,
            audit.single_frame_messages,
            audit.bam_started,
            audit.bam_completed,
            audit.unsupported_transport_controls,
            audit.assembly_errors,
            audit.eec1_engine_speed_observations,
            audit.dm1_lamp_observations,
            audit.dm1_dtc_observations,
            audit.unsupported_pgn_messages,
            audit.decode_errors,
        },
    );
}
