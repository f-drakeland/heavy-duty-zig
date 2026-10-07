const std = @import("std");
const Io = std.Io;

const capture_pipeline = @import("capture_pipeline.zig");
const j1587 = @import("j1587.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);

    if (args.len != 2) {
        try Io.File.stderr().writeStreamingAll(
            io,
            "usage: capture_inspect <capture-file>\n",
        );
        return;
    }

    const path = args[1];

    const input = try Io.Dir.cwd().readFileAlloc(
        io,
        path,
        arena,
        .limited(16 * 1024 * 1024),
    );

    var byte_storage: [4096]u8 = undefined;
    var scratch: [4097]@import("frame_recovery.zig").ScratchState =
        undefined;

    var decoder = j1587.Decoder.init();

    var capture = capture_pipeline.CaptureCursor.init(
        input,
        &byte_storage,
        &scratch,
        &decoder,
    );

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer =
        Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var event_count: usize = 0;

    while (try capture.next()) |output| {
        switch (output) {
            .audit => |audit| {
                try stdout.print(
                    "line {d}: {s}\n",
                    .{
                        audit.line_number,
                        @tagName(audit.status),
                    },
                );
            },

            .event => |event_entry| {
                event_count += 1;

                switch (event_entry.event) {
                    .unhandled_frame => |frame| {
                        try stdout.print(
                            "line {d}: J1708 frame MID {d} ({d} bytes), {s}\n",
                            .{
                                event_entry.line_number,
                                frame.mid,
                                frame.byte_length,
                                @tagName(frame.reason),
                            },
                        );
                    },

                    .j1587 => |j1587_event| {
                        switch (j1587_event) {
                            .unsupported_parameter => |unsupported| {
                                try stdout.print(
                                    "line {d}: unsupported PID {d} from MID {d} ({d} bytes)\n",
                                    .{
                                        event_entry.line_number,
                                        unsupported.pid,
                                        unsupported.source_mid,
                                        unsupported.data_length,
                                    },
                                );
                            },

                            .observation => |observation| {
                                switch (observation) {
                                    .software_identification => |software| {
                                        try stdout.print(
                                            "line {d}: software MID {d} \"{s}\"\n",
                                            .{
                                                event_entry.line_number,
                                                software.source_mid,
                                                software.value,
                                            },
                                        );
                                    },

                                    .vin => |vin| {
                                        try stdout.print(
                                            "line {d}: VIN MID {d} \"{s}\"\n",
                                            .{
                                                event_entry.line_number,
                                                vin.source_mid,
                                                vin.value,
                                            },
                                        );
                                    },

                                    .component_identification => |component| {
                                        const display_manufacturer = std.mem.trim(
                                            u8,
                                            component.manufacturer,
                                            " \x00",
                                        );

                                        const display_model = std.mem.trim(
                                            u8,
                                            component.model_name,
                                            " \x00",
                                        );

                                        const display_serial = std.mem.trim(
                                            u8,
                                            component.serial,
                                            " \x00",
                                        );

                                        try stdout.print(
                                            "line {d}: component source MID {d}, component MID {d}, manufacturer \"{s}\", model \"{s}\", serial \"{s}\"\n",
                                            .{
                                                event_entry.line_number,
                                                component.source_mid,
                                                component.component_mid,
                                                display_manufacturer,
                                                display_model,
                                                display_serial,
                                            },
                                        );
                                    },

                                    .road_speed => |speed| {
                                        try stdout.print(
                                            "line {d}: road speed MID {d}, raw {d}, {d:.2} km/h, {d:.2} mph\n",
                                            .{
                                                event_entry.line_number,
                                                speed.source_mid,
                                                speed.raw_count,
                                                speed.kilometers_per_hour,
                                                speed.miles_per_hour,
                                            },
                                        );
                                    },

                                    .accelerator_pedal_position => |position| {
                                        try stdout.print(
                                            "line {d}: accelerator pedal MID {d}, raw {d}, {d:.2}%\n",
                                            .{
                                                event_entry.line_number,
                                                position.source_mid,
                                                position.raw_count,
                                                position.percent,
                                            },
                                        );
                                    },

                                    .engine_load => |load| {
                                        try stdout.print(
                                            "line {d}: engine load MID {d}, raw {d}, {d:.2}%\n",
                                            .{
                                                event_entry.line_number,
                                                load.source_mid,
                                                load.raw_count,
                                                load.percent,
                                            },
                                        );
                                    },

                                    .engine_speed => |speed| {
                                        try stdout.print(
                                            "line {d}: engine speed MID {d}, raw {d}, {d:.2} rpm\n",
                                            .{
                                                event_entry.line_number,
                                                speed.source_mid,
                                                speed.raw_count,
                                                speed.rpm,
                                            },
                                        );
                                    },

                                    .vehicle_distance => |distance| {
                                        try stdout.print(
                                            "line {d}: vehicle distance MID {d}, raw {d}, {d:.2} km, {d:.2} mi\n",
                                            .{
                                                event_entry.line_number,
                                                distance.source_mid,
                                                distance.raw_count,
                                                distance.kilometers,
                                                distance.miles,
                                            },
                                        );
                                    },

                                    .diagnostic_code => |code| {
                                        if (code.occurrence_count) |count| {
                                            try stdout.print(
                                                "line {d}: diagnostic MID {d}, {s} {d}, FMI {d}, {s}, occurrences {d}\n",
                                                .{
                                                    event_entry.line_number,
                                                    code.source_mid,
                                                    @tagName(code.identifier_kind),
                                                    code.identifier,
                                                    code.fmi,
                                                    @tagName(code.status),
                                                    count,
                                                },
                                            );
                                        } else {
                                            try stdout.print(
                                                "line {d}: diagnostic MID {d}, {s} {d}, FMI {d}, {s}\n",
                                                .{
                                                    event_entry.line_number,
                                                    code.source_mid,
                                                    @tagName(code.identifier_kind),
                                                    code.identifier,
                                                    code.fmi,
                                                    @tagName(code.status),
                                                },
                                            );
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            },
        }
    }

    const summary = capture.summary();

    try stdout.print(
        "\nCapture summary\n" ++
            "records:       {d}\n" ++
            "recovered:     {d}\n" ++
            "ambiguous:     {d}\n" ++
            "unrecoverable: {d}\n" ++
            "rejected:      {d}\n" ++
            "events:        {d}\n",
        .{
            summary.records,
            summary.recovered,
            summary.ambiguous,
            summary.unrecoverable,
            summary.rejected,
            event_count,
        },
    );

    try stdout.flush();
}
