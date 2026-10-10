const std = @import("std");
const Io = std.Io;

const ddec_csv = @import("ddec_csv.zig");
const j1939 = @import("j1939.zig");
const correlation = @import("correlation.zig");
// Operational bound for this whole-file developer CLI.
// This is not a DDEC, CAN, or J1939 protocol limit.
const max_capture_bytes =
    64 * 1024 * 1024;

const pgn_inventory_capacity = 4096;

const PgnInventoryError = error{
    PgnInventoryCapacityExceeded,
};

const PgnInventory = struct {
    const Entry = struct {
        occupied: bool = false,
        source_address: u8 = 0,
        destination_address: ?u8 = null,
        pgn: u32 = 0,
        message_count: usize = 0,
    };

    entries: [pgn_inventory_capacity]Entry =
        @splat(.{}),

    entry_count: usize = 0,

    fn observe(
        self: *PgnInventory,
        source_address: u8,
        destination_address: ?u8,
        pgn: u32,
    ) PgnInventoryError!void {
        for (&self.entries) |*entry| {
            if (entry.occupied and
                entry.source_address == source_address and
                entry.destination_address == destination_address and
                entry.pgn == pgn)
            {
                entry.message_count += 1;
                return;
            }
        }

        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.* = .{
                    .occupied = true,
                    .source_address = source_address,
                    .destination_address = destination_address,
                    .pgn = pgn,
                    .message_count = 1,
                };

                self.entry_count += 1;
                return;
            }
        }

        return error.PgnInventoryCapacityExceeded;
    }
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    const args =
        try init.minimal.args.toSlice(arena);

    if (args.len != 2) {
        std.debug.print(
            "usage: ddec_j1939_inspect <capture-file>\n",
            .{},
        );
        return;
    }

    const text =
        try Io.Dir.cwd().readFileAlloc(
            io,
            args[1],
            arena,
            .limited(max_capture_bytes),
        );

    var lines_seen: usize = 0;
    var non_can_lines: usize = 0;
    var ddec_parse_rejected: usize = 0;

    var standard_can_frames: usize = 0;
    var extended_can_frames: usize = 0;

    var j1939_frames: usize = 0;
    var next_frame_occurrence_index: usize = 0;
    var j1939_rejected: usize = 0;

    var messages: usize = 0;
    var assembly_errors: usize = 0;
    var decode_errors: usize = 0;

    var typed_observations: usize = 0;
    var unsupported_pgn_messages: usize = 0;

    var pgn_inventory = PgnInventory{};

    var assembler =
        j1939.MessageAssembler(
            j1939.transport.reassembly.maximum_message_size,
            4,
        ){};

    var endpoints =
        correlation.EndpointInventory(256){};

    var diagnostics =
        correlation.DiagnosticEvidenceInventory(1024){};

    var identities =
        correlation.IdentityEvidenceInventory(
            1024,
            j1939.transport.reassembly.maximum_message_size,
        ){};

    var lines =
        std.mem.splitScalar(
            u8,
            text,
            '\n',
        );

    while (lines.next()) |line| {
        const trimmed =
            std.mem.trim(
                u8,
                line,
                " \t\r",
            );

        if (trimmed.len == 0) {
            continue;
        }

        lines_seen += 1;

        const parsed =
            ddec_csv.parseLine(
                trimmed,
            ) catch {
                ddec_parse_rejected += 1;
                continue;
            };

        const record = switch (parsed) {
            .non_can => {
                non_can_lines += 1;
                continue;
            },

            .can => |record| record,
        };
        const frame_occurrence_index =
            next_frame_occurrence_index;

        next_frame_occurrence_index += 1;

        switch (record.identifier_format) {
            .standard => {
                standard_can_frames += 1;
                continue;
            },

            .extended => {
                extended_can_frames += 1;
            },
        }

        const can_frame =
            record.frame() catch {
                j1939_rejected += 1;
                continue;
            };

        const frame =
            j1939.FrameView.fromCanFrame(
                can_frame,
            ) catch {
                j1939_rejected += 1;
                continue;
            };

        j1939_frames += 1;

        const source_address =
            frame.identifier().source_address;

        _ = endpoints.observePresence(.{
            .j1939_source_address = source_address,
        }) catch |err| {
            std.debug.print(
                "endpoint presence inventory error: {s}\n",
                .{@errorName(err)},
            );
            return;
        };

        const assembly_result =
            assembler.pushFrameWithDerivation(
                frame,
            ) catch {
                assembly_errors += 1;
                continue;
            };

        const maybe_assembly_event =
            assembly_result.event;

        switch (assembly_result.derivation) {
            .transport_started => |transfer| {
                if (transfer.target_pgn ==
                    j1939.pgn_component_identification)
                {
                    std.debug.print(
                        "lineage occurrence #{} timestamp={s} {s} ch:{}: TP start {X:0>2}->{X:0>2} PGN 0x{X:0>6} {s}\n",
                        .{
                            frame_occurrence_index,
                            record.timestamp_text,
                            @tagName(record.direction),
                            record.channel,
                            transfer.source_address,
                            transfer.destination_address,
                            transfer.target_pgn,
                            @tagName(transfer.delivery),
                        },
                    );
                }
            },

            .transport_context => |transfer| {
                if (transfer.target_pgn ==
                    j1939.pgn_component_identification)
                {
                    std.debug.print(
                        "lineage occurrence #{} timestamp={s} {s} ch:{}: TP context for transfer {X:0>2}->{X:0>2} PGN 0x{X:0>6} {s}\n",
                        .{
                            frame_occurrence_index,
                            record.timestamp_text,
                            @tagName(record.direction),
                            record.channel,
                            transfer.source_address,
                            transfer.destination_address,
                            transfer.target_pgn,
                            @tagName(transfer.delivery),
                        },
                    );
                }
            },

            .transport_payload => |derivation| {
                if (derivation.transfer.target_pgn ==
                    j1939.pgn_component_identification)
                {
                    std.debug.print(
                        "lineage occurrence #{} timestamp={s} {s} ch:{}: TP payload {X:0>2}->{X:0>2} PGN 0x{X:0>6} offset={} length={} {s}\n",
                        .{
                            frame_occurrence_index,
                            record.timestamp_text,
                            @tagName(record.direction),
                            record.channel,
                            derivation.transfer.source_address,
                            derivation.transfer.destination_address,
                            derivation.transfer.target_pgn,
                            derivation.contribution.offset,
                            derivation.contribution.byte_length,
                            @tagName(derivation.transfer.delivery),
                        },
                    );
                }
            },

            .none => {},
            .direct_message => {},
        }

        const assembly_event =
            maybe_assembly_event orelse
            continue;

        switch (assembly_event) {
            .message => |message| {
                messages += 1;

                pgn_inventory.observe(
                    message.sourceAddress(),
                    message.destinationAddress(),
                    message.pgn(),
                ) catch |err| {
                    std.debug.print(
                        "PGN inventory error: {s}\n",
                        .{@errorName(err)},
                    );
                    return;
                };

                var cursor =
                    j1939.MessageCursor.init(
                        message,
                    ) catch {
                        decode_errors += 1;
                        continue;
                    };

                while (true) {
                    const maybe_event =
                        cursor.next() catch {
                            decode_errors += 1;
                            break;
                        };

                    const event =
                        maybe_event orelse
                        break;

                    switch (event) {
                        .unsupported_pgn => {
                            unsupported_pgn_messages += 1;
                        },

                        .observation => |observation| {
                            typed_observations += 1;

                            const endpoint_observation =
                                correlation.fromJ1939(
                                    observation,
                                );

                            _ = endpoints.observe(
                                endpoint_observation,
                            ) catch |err| {
                                std.debug.print(
                                    "endpoint inventory error: {s}\n",
                                    .{@errorName(err)},
                                );
                                return;
                            };

                            _ = diagnostics.observe(
                                endpoint_observation,
                            ) catch |err| {
                                std.debug.print(
                                    "diagnostic inventory error: {s}\n",
                                    .{@errorName(err)},
                                );
                                return;
                            };

                            _ = identities.observe(
                                endpoint_observation,
                            ) catch |err| {
                                std.debug.print(
                                    "identity inventory error: {s}\n",
                                    .{@errorName(err)},
                                );
                                return;
                            };
                        },
                    }
                }
            },

            else => {},
        }
    }

    const View =
        correlation.CaptureDiagnosticView(
            256,
            1024,
            j1939.transport.reassembly.maximum_message_size,
            1024,
        );

    const view =
        View.init(
            &endpoints,
            &identities,
            &diagnostics,
        );

    std.debug.print(
        \\lines seen: {}
        \\non-CAN lines: {}
        \\DDEC parse rejected: {}
        \\standard CAN frames: {}
        \\extended CAN frames: {}
        \\J1939 frames: {}
        \\J1939 rejected: {}
        \\logical messages: {}
        \\assembly errors: {}
        \\decode errors: {}
        \\typed observations: {}
        \\unsupported PGN messages: {}
        \\capture-local endpoints: {}
        \\distinct identity evidence: {}
        \\distinct diagnostic evidence: {}
        \\
    ,
        .{
            lines_seen,
            non_can_lines,
            ddec_parse_rejected,
            standard_can_frames,
            extended_can_frames,
            j1939_frames,
            j1939_rejected,
            messages,
            assembly_errors,
            decode_errors,
            typed_observations,
            unsupported_pgn_messages,
            view.count(),
            identities.count(),
            diagnostics.count(),
        },
    );

    var endpoint_index: usize = 0;

    while (view.endpointAt(endpoint_index)) |endpoint| : (endpoint_index += 1) {
        switch (endpoint.key) {
            .j1939_source_address => |source_address| {
                std.debug.print(
                    "\nJ1939 SA {X:0>2}: presence={} observations={} identity evidence={} diagnostic evidence={}\n",
                    .{
                        source_address,
                        endpoint.presence_count,
                        endpoint.observation_count,
                        endpoint.identity_evidence_count,
                        endpoint.diagnostic_evidence_count,
                    },
                );

                for (pgn_inventory.entries) |entry| {
                    if (!entry.occupied or
                        entry.source_address != source_address)
                    {
                        continue;
                    }

                    if (entry.destination_address) |destination_address| {
                        std.debug.print(
                            "  PGN 0x{X:0>6} -> delivery DA {X:0>2}: {} messages\n",
                            .{
                                entry.pgn,
                                destination_address,
                                entry.message_count,
                            },
                        );
                    } else {
                        std.debug.print(
                            "  PGN 0x{X:0>6} -> PDU2: {} messages\n",
                            .{
                                entry.pgn,
                                entry.message_count,
                            },
                        );
                    }
                }
            },

            .j1587_mid => |mid| {
                std.debug.print(
                    "\nJ1587 MID {d}: presence={} observations={} identity evidence={} diagnostic evidence={}\n",
                    .{
                        mid,
                        endpoint.presence_count,
                        endpoint.observation_count,
                        endpoint.identity_evidence_count,
                        endpoint.diagnostic_evidence_count,
                    },
                );
            },
        }

        var diagnostic_index: usize = 0;

        while (view.diagnosticEvidenceAt(
            endpoint.key,
            diagnostic_index,
        )) |diagnostic| : (diagnostic_index += 1) {
            std.debug.print(
                "  diagnostic evidence #{d} capture observations={}: ",
                .{
                    diagnostic_index,
                    diagnostic.capture_observation_count,
                },
            );

            switch (diagnostic.evidence.*) {
                .j1587_diagnostic_code => |value| {
                    std.debug.print(
                        "J1587 diagnostic code {any}\n",
                        .{value},
                    );
                },

                .j1939_dm1_lamps => |value| {
                    std.debug.print(
                        "J1939 DM1 lamps delivery={s} statuses={any} flashes={any}\n",
                        .{
                            @tagName(value.delivery),
                            value.statuses,
                            value.flashes,
                        },
                    );
                },

                .j1939_dm1_diagnostic_trouble_code => |value| {
                    std.debug.print(
                        "J1939 DM1 DTC delivery={s} trouble_code={any}\n",
                        .{
                            @tagName(value.delivery),
                            value.trouble_code,
                        },
                    );
                },
            }
        }

        var identity_index: usize = 0;

        while (view.identityEvidenceAt(
            endpoint.key,
            identity_index,
        )) |identity| : (identity_index += 1) {
            std.debug.print(
                "  identity evidence #{d} occurrences={}: ",
                .{
                    identity_index,
                    identity.occurrence_count,
                },
            );

            switch (identity.observation.evidence) {
                .j1939_address_claim => |claim| {
                    std.debug.print(
                        "J1939 NAME 0x{X:0>16}\n",
                        .{claim.name.raw},
                    );
                },

                .j1939_component_identification => |component| {
                    std.debug.print(
                        "J1939 component make=\"{s}\" model=\"{s}\" serial=\"{s}\" unit=\"{s}\"\n",
                        .{
                            component.fields.field(0),
                            component.fields.field(1),
                            component.fields.field(2),
                            component.fields.field(3),
                        },
                    );
                },

                .j1587_software_identification,
                .j1587_vin,
                .j1587_component_identification,
                => {
                    std.debug.print(
                        "unexpected J1587 evidence in J1939 inspection\n",
                        .{},
                    );
                },
            }
        }
    }
}
