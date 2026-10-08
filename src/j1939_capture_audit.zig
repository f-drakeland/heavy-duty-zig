const std = @import("std");
const candump = @import("candump.zig");
const j1939 = @import("j1939.zig");

pub const Audit = struct {
    records_seen: usize = 0,
    records_parsed: usize = 0,
    parse_rejected: usize = 0,

    j1939_frames: usize = 0,
    j1939_rejected: usize = 0,

    tp_cm_frames: usize = 0,
    tp_dt_frames: usize = 0,
    direct_dm1_frames: usize = 0,

    single_frame_messages: usize = 0,
    bam_started: usize = 0,
    bam_completed: usize = 0,
    unsupported_transport_controls: usize = 0,
    assembly_errors: usize = 0,

    dm1_lamp_observations: usize = 0,
    dm1_dtc_observations: usize = 0,
    unsupported_pgn_messages: usize = 0,
    decode_errors: usize = 0,
};

fn auditMessage(
    audit: *Audit,
    message: j1939.MessageView,
) void {
    switch (message.delivery()) {
        .single_frame => audit.single_frame_messages += 1,

        .bam => audit.bam_completed += 1,
    }

    var cursor =
        j1939.MessageCursor.init(message) catch {
            audit.decode_errors += 1;
            return;
        };

    while (true) {
        const maybe_event =
            cursor.next() catch {
                audit.decode_errors += 1;
                return;
            };

        const event =
            maybe_event orelse break;

        switch (event) {
            .unsupported_pgn => {
                audit.unsupported_pgn_messages += 1;
            },

            .observation => |observation| {
                switch (observation) {
                    .dm1_lamps => {
                        audit.dm1_lamp_observations += 1;
                    },

                    .dm1_diagnostic_trouble_code => {
                        audit.dm1_dtc_observations += 1;
                    },
                }
            },
        }
    }
}

pub fn auditText(
    comptime message_capacity: usize,
    comptime session_capacity: usize,
    text: []const u8,
) Audit {
    var audit = Audit{};

    var assembler =
        j1939.MessageAssembler(
            message_capacity,
            session_capacity,
        ){};

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
                audit.parse_rejected += 1;
                continue;
            };

        audit.records_parsed += 1;

        const can_frame =
            record.frame() catch {
                audit.j1939_rejected += 1;
                continue;
            };

        const frame =
            j1939.FrameView.fromCanFrame(
                can_frame,
            ) catch {
                audit.j1939_rejected += 1;
                continue;
            };

        audit.j1939_frames += 1;

        switch (frame.pgnClassification()) {
            .transport_connection_management => audit.tp_cm_frames += 1,

            .transport_data_transfer => audit.tp_dt_frames += 1,

            .diagnostic_message_1 => audit.direct_dm1_frames += 1,

            .unsupported => {},
        }

        const maybe_assembly_event =
            assembler.pushFrame(frame) catch {
                audit.assembly_errors += 1;
                continue;
            };

        const assembly_event =
            maybe_assembly_event orelse
            continue;

        switch (assembly_event) {
            .bam_started => {
                audit.bam_started += 1;
            },

            .unsupported_transport_control => {
                audit.unsupported_transport_controls += 1;
            },

            .message => |message| {
                auditMessage(
                    &audit,
                    message,
                );
            },
        }
    }

    return audit;
}

test "audits direct DM1 through J1939 pipeline" {
    const text =
        \\(001.000000) can1 18FECA80 [8] 00 FF 00 00 00 00 FF FF
    ;

    const audit =
        auditText(
            64,
            4,
            text,
        );

    try std.testing.expectEqual(
        @as(usize, 1),
        audit.records_seen,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        audit.records_parsed,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        audit.j1939_frames,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        audit.direct_dm1_frames,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        audit.single_frame_messages,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        audit.dm1_lamp_observations,
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        audit.dm1_dtc_observations,
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        audit.assembly_errors,
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        audit.decode_errors,
    );
}
