const std = @import("std");

const Io = std.Io;

const ddec_csv = @import("ddec_csv.zig");
const isotp = @import("isotp.zig");

// Operational bound for this whole-file developer CLI.
// This is not a DDEC, CAN, or ISO-TP protocol limit.
const max_capture_bytes =
    64 * 1024 * 1024;

// Operational bounds for this inspection tool.
// These are not protocol limits.
const pair_inventory_capacity = 64;
const session_capacity = 16;
const payload_capacity = 4095;

const PairInventoryError = error{
    PairInventoryCapacityExceeded,
};

const PairInventory = struct {
    const Entry = struct {
        occupied: bool = false,

        source_address: u8 = 0,
        destination_address: u8 = 0,

        frame_count: usize = 0,

        single_frames: usize = 0,
        first_frames: usize = 0,
        consecutive_frames: usize = 0,
        flow_control_frames: usize = 0,
        unsupported_pci_frames: usize = 0,

        completed_single_messages: usize = 0,
        completed_multi_messages: usize = 0,

        matched_flow_controls: usize = 0,
        unmatched_flow_controls: usize = 0,
    };

    entries: [pair_inventory_capacity]Entry =
        @splat(.{}),

    entry_count: usize = 0,

    fn observeFrame(
        self: *PairInventory,
        source_address: u8,
        destination_address: u8,
        frame: isotp.Frame,
    ) PairInventoryError!*Entry {
        var entry: ?*Entry = null;

        for (&self.entries) |*candidate| {
            if (candidate.occupied and
                candidate.source_address ==
                    source_address and
                candidate.destination_address ==
                    destination_address)
            {
                entry = candidate;
                break;
            }
        }

        if (entry == null) {
            for (&self.entries) |*candidate| {
                if (!candidate.occupied) {
                    candidate.* = .{
                        .occupied = true,
                        .source_address = source_address,
                        .destination_address = destination_address,
                    };

                    self.entry_count += 1;
                    entry = candidate;
                    break;
                }
            }
        }

        const observed =
            entry orelse
            return error.PairInventoryCapacityExceeded;

        observed.frame_count += 1;

        switch (frame) {
            .single_frame => {
                observed.single_frames += 1;
            },

            .first_frame => {
                observed.first_frames += 1;
            },

            .consecutive_frame => {
                observed.consecutive_frames += 1;
            },

            .flow_control => {
                observed.flow_control_frames += 1;
            },

            .unsupported => {
                observed.unsupported_pci_frames += 1;
            },
        }

        return observed;
    }
};

fn isObserved18DaIdentifier(
    identifier: u32,
) bool {
    return (identifier & 0x1fff0000) ==
        0x18da0000;
}

fn sourceAddress(
    identifier: u32,
) u8 {
    return @truncate(identifier);
}

fn destinationAddress(
    identifier: u32,
) u8 {
    return @truncate(identifier >> 8);
}

pub fn main(
    init: std.process.Init,
) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    const args =
        try init.minimal.args.toSlice(arena);

    if (args.len != 2) {
        std.debug.print(
            "usage: ddec_isotp_inspect <capture-file>\n",
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

    var observed_18da_frames: usize = 0;

    var single_frames: usize = 0;
    var first_frames: usize = 0;
    var consecutive_frames: usize = 0;
    var flow_control_frames: usize = 0;
    var unsupported_pci_frames: usize = 0;

    var isotp_parse_rejected: usize = 0;

    var completed_messages: usize = 0;
    var completed_single_messages: usize = 0;
    var completed_multi_messages: usize = 0;

    var matched_flow_controls: usize = 0;
    var unmatched_flow_controls: usize = 0;

    var capacity_exceeded: usize = 0;
    var transfer_already_active: usize = 0;
    var no_active_transfer: usize = 0;
    var unexpected_sequence_number: usize = 0;
    var unsupported_frame_type: usize = 0;
    var session_capacity_exceeded: usize = 0;

    var pairs = PairInventory{};

    var router =
        isotp.SessionRouter(
            session_capacity,
            payload_capacity,
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
                ddec_parse_rejected += 1;
                continue;
            };

        const identifier =
            can_frame.identifier();

        if (!isObserved18DaIdentifier(
            identifier,
        )) {
            continue;
        }

        observed_18da_frames += 1;

        const source_address =
            sourceAddress(identifier);

        const destination_address =
            destinationAddress(identifier);

        const frame =
            isotp.parse(
                can_frame.data(),
            ) catch {
                isotp_parse_rejected += 1;
                continue;
            };

        switch (frame) {
            .single_frame => {
                single_frames += 1;
            },

            .first_frame => {
                first_frames += 1;
            },

            .consecutive_frame => {
                consecutive_frames += 1;
            },

            .flow_control => {
                flow_control_frames += 1;
            },

            .unsupported => {
                unsupported_pci_frames += 1;
            },
        }

        const pair =
            pairs.observeFrame(
                source_address,
                destination_address,
                frame,
            ) catch |err| {
                std.debug.print(
                    "pair inventory error: {s}\n",
                    .{@errorName(err)},
                );

                return;
            };

        if (frame == .unsupported) {
            continue;
        }

        const event =
            router.push(
                source_address,
                destination_address,
                frame,
            ) catch |err| {
                switch (err) {
                    error.CapacityExceeded => {
                        capacity_exceeded += 1;
                    },

                    error.TransferAlreadyActive => {
                        transfer_already_active += 1;
                    },

                    error.NoActiveTransfer => {
                        no_active_transfer += 1;
                    },

                    error.UnexpectedSequenceNumber => {
                        unexpected_sequence_number += 1;
                    },

                    error.UnsupportedFrameType => {
                        unsupported_frame_type += 1;
                    },

                    error.SessionCapacityExceeded => {
                        session_capacity_exceeded += 1;
                    },
                }

                continue;
            };

        switch (event) {
            .in_progress => {},

            .completed => |message| {
                completed_messages += 1;

                switch (message.delivery) {
                    .single_frame => {
                        completed_single_messages += 1;
                        pair.completed_single_messages += 1;
                    },

                    .multi_frame => {
                        completed_multi_messages += 1;
                        pair.completed_multi_messages += 1;
                    },
                }
            },

            .flow_control => |flow_control| {
                if (flow_control
                    .matched_active_transfer)
                {
                    matched_flow_controls += 1;
                    pair.matched_flow_controls += 1;
                } else {
                    unmatched_flow_controls += 1;
                    pair.unmatched_flow_controls += 1;
                }
            },
        }
    }

    std.debug.print(
        \\lines seen: {}
        \\non-CAN lines: {}
        \\DDEC parse rejected: {}
        \\standard CAN frames: {}
        \\extended CAN frames: {}
        \\observed 18DA frames: {}
        \\ISO-TP parse rejected: {}
        \\single frames: {}
        \\first frames: {}
        \\consecutive frames: {}
        \\flow control frames: {}
        \\unsupported PCI frames: {}
        \\completed messages: {}
        \\completed single-frame messages: {}
        \\completed multi-frame messages: {}
        \\matched flow controls: {}
        \\unmatched flow controls: {}
        \\capacity exceeded: {}
        \\transfer already active: {}
        \\no active transfer: {}
        \\unexpected sequence number: {}
        \\unsupported frame type: {}
        \\session capacity exceeded: {}
        \\address pairs: {}
        \\
    ,
        .{
            lines_seen,
            non_can_lines,
            ddec_parse_rejected,
            standard_can_frames,
            extended_can_frames,
            observed_18da_frames,
            isotp_parse_rejected,
            single_frames,
            first_frames,
            consecutive_frames,
            flow_control_frames,
            unsupported_pci_frames,
            completed_messages,
            completed_single_messages,
            completed_multi_messages,
            matched_flow_controls,
            unmatched_flow_controls,
            capacity_exceeded,
            transfer_already_active,
            no_active_transfer,
            unexpected_sequence_number,
            unsupported_frame_type,
            session_capacity_exceeded,
            pairs.entry_count,
        },
    );

    for (pairs.entries) |entry| {
        if (!entry.occupied) {
            continue;
        }

        std.debug.print(
            \\
            \\ISO-TP {X:0>2} -> {X:0>2}
            \\  frames: {}
            \\  single: {}
            \\  first: {}
            \\  consecutive: {}
            \\  flow control: {}
            \\  unsupported PCI: {}
            \\  completed single messages: {}
            \\  completed multi messages: {}
            \\  matched flow controls: {}
            \\  unmatched flow controls: {}
            \\
        ,
            .{
                entry.source_address,
                entry.destination_address,
                entry.frame_count,
                entry.single_frames,
                entry.first_frames,
                entry.consecutive_frames,
                entry.flow_control_frames,
                entry.unsupported_pci_frames,
                entry.completed_single_messages,
                entry.completed_multi_messages,
                entry.matched_flow_controls,
                entry.unmatched_flow_controls,
            },
        );
    }
}
