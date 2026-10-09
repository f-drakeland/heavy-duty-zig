const std = @import("std");

const Io = std.Io;

const ddec_csv = @import("ddec_csv.zig");
const isotp = @import("isotp.zig");
const uds = @import("uds.zig");

// Operational bound for this whole-file developer CLI.
// This is not a DDEC, CAN, or ISO-TP protocol limit.
const max_capture_bytes =
    64 * 1024 * 1024;

// Operational bounds for this inspection tool.
// These are not protocol limits.
const pair_inventory_capacity = 64;
const session_capacity = 16;
const payload_capacity = 4095;

const did_inventory_capacity = 256;
const did_value_sample_capacity = 256;

const DidInventoryError = error{
    DidInventoryCapacityExceeded,
};

const DidInventory = struct {
    const Entry = struct {
        occupied: bool = false,
        did: u16 = 0,
        request_count: usize = 0,
        positive_response_count: usize = 0,
        value_min_length: usize = 0,
        value_max_length: usize = 0,

        printable_or_nul_responses: usize = 0,

        first_value: [did_value_sample_capacity]u8 = undefined,
        first_value_length: usize = 0,
        first_value_stored: bool = false,

        comparison_limited: bool = false,
        value_changed: bool = false,
    };

    entries: [did_inventory_capacity]Entry =
        @splat(.{}),

    entry_count: usize = 0,

    fn observeRequest(
        self: *DidInventory,
        did: u16,
    ) DidInventoryError!void {
        for (&self.entries) |*entry| {
            if (entry.occupied and
                entry.did == did)
            {
                entry.request_count += 1;
                return;
            }
        }

        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.* = .{
                    .occupied = true,
                    .did = did,
                    .request_count = 1,
                };

                self.entry_count += 1;
                return;
            }
        }

        return error.DidInventoryCapacityExceeded;
    }
    fn observePositiveResponse(
        self: *DidInventory,
        did: u16,
        value: []const u8,
    ) DidInventoryError!void {
        for (&self.entries) |*entry| {
            if (entry.occupied and
                entry.did == did)
            {
                recordPositiveResponse(
                    entry,
                    value,
                );

                return;
            }
        }

        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.* = .{
                    .occupied = true,
                    .did = did,
                };

                recordPositiveResponse(
                    entry,
                    value,
                );

                self.entry_count += 1;
                return;
            }
        }

        return error.DidInventoryCapacityExceeded;
    }

    fn recordPositiveResponse(
        entry: *Entry,
        value: []const u8,
    ) void {
        const first_response =
            entry.positive_response_count == 0;

        entry.positive_response_count += 1;

        if (first_response) {
            entry.value_min_length = value.len;
            entry.value_max_length = value.len;
        } else {
            entry.value_min_length =
                @min(
                    entry.value_min_length,
                    value.len,
                );

            entry.value_max_length =
                @max(
                    entry.value_max_length,
                    value.len,
                );
        }

        if (isPrintableOrNul(value)) {
            entry.printable_or_nul_responses += 1;
        }

        if (first_response) {
            if (value.len >
                did_value_sample_capacity)
            {
                entry.comparison_limited = true;
                return;
            }

            std.mem.copyForwards(
                u8,
                entry.first_value[0..value.len],
                value,
            );

            entry.first_value_length =
                value.len;

            entry.first_value_stored = true;
            return;
        }

        if (entry.first_value_stored and
            value.len !=
                entry.first_value_length)
        {
            entry.value_changed = true;
        }

        if (value.len >
            did_value_sample_capacity)
        {
            entry.comparison_limited = true;
            return;
        }

        if (!entry.first_value_stored) {
            entry.comparison_limited = true;
            return;
        }

        if (!std.mem.eql(
            u8,
            entry.first_value[0..entry.first_value_length],
            value,
        )) {
            entry.value_changed = true;
        }
    }

    fn isPrintableOrNul(
        value: []const u8,
    ) bool {
        if (value.len == 0) {
            return false;
        }

        for (value) |byte| {
            if (byte == 0x00) {
                continue;
            }

            if (byte < 0x20 or
                byte > 0x7e)
            {
                return false;
            }
        }

        return true;
    }
};

const uds_inventory_capacity = 64;

const UdsInventoryError = error{
    UdsInventoryCapacityExceeded,
};

const UdsInventory = struct {
    const Kind = enum {
        request_or_service,
        positive_response,
        negative_response,
    };

    const Entry = struct {
        occupied: bool = false,

        source_address: u8 = 0,
        destination_address: u8 = 0,

        kind: Kind = .request_or_service,

        service_id: u8 = 0,

        request_service_id: ?u8 = null,
        response_code: ?u8 = null,

        message_count: usize = 0,
    };

    entries: [uds_inventory_capacity]Entry =
        @splat(.{}),

    entry_count: usize = 0,

    fn observe(
        self: *UdsInventory,
        source_address: u8,
        destination_address: u8,
        message: uds.Message,
    ) UdsInventoryError!void {
        const kind: Kind = switch (message) {
            .service => |service| if (service.positive_response_to != null)
                .positive_response
            else
                .request_or_service,

            .negative_response => .negative_response,
        };

        const service_id: u8 = switch (message) {
            .service => |service| service.service_id,

            .negative_response => 0x7f,
        };

        const request_service_id: ?u8 =
            switch (message) {
                .service => |service| service.positive_response_to,

                .negative_response => |negative| negative.request_service_id,
            };

        const response_code: ?u8 =
            switch (message) {
                .service => null,

                .negative_response => |negative| negative.response_code,
            };

        for (&self.entries) |*entry| {
            if (entry.occupied and
                entry.source_address ==
                    source_address and
                entry.destination_address ==
                    destination_address and
                entry.kind == kind and
                entry.service_id ==
                    service_id and
                entry.request_service_id ==
                    request_service_id and
                entry.response_code ==
                    response_code)
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
                    .kind = kind,
                    .service_id = service_id,
                    .request_service_id = request_service_id,
                    .response_code = response_code,
                    .message_count = 1,
                };

                self.entry_count += 1;
                return;
            }
        }

        return error.UdsInventoryCapacityExceeded;
    }
};

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
    var uds_messages: usize = 0;
    var uds_parse_rejected: usize = 0;
    var negative_responses: usize = 0;

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
    var uds_inventory = UdsInventory{};
    var did_inventory = DidInventory{};

    var read_did_requests: usize = 0;
    var read_did_identifiers: usize = 0;
    var malformed_read_did_requests: usize = 0;
    var multi_did_requests: usize = 0;
    var read_did_positive_responses: usize = 0;
    var malformed_read_did_positive_responses: usize = 0;

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

                const uds_message =
                    uds.parse(
                        message.payload,
                    ) catch {
                        uds_parse_rejected += 1;
                        continue;
                    };

                uds_messages += 1;

                switch (uds_message) {
                    .negative_response => {
                        negative_responses += 1;
                    },

                    .service => {},
                }

                uds_inventory.observe(
                    message.source_address,
                    message.destination_address,
                    uds_message,
                ) catch |err| {
                    std.debug.print(
                        "UDS inventory error: {s}\n",
                        .{@errorName(err)},
                    );

                    return;
                };
                switch (uds_message) {
                    .service => |service| {
                        if (service.service_id == 0x22) {
                            read_did_requests += 1;

                            if (service.data.len == 0 or
                                service.data.len % 2 != 0)
                            {
                                malformed_read_did_requests += 1;
                                continue;
                            }

                            const did_count =
                                service.data.len / 2;

                            if (did_count > 1) {
                                multi_did_requests += 1;
                            }

                            var offset: usize = 0;

                            while (offset < service.data.len) : (offset += 2) {
                                const did =
                                    (@as(u16, service.data[offset]) << 8) |
                                    @as(u16, service.data[offset + 1]);

                                did_inventory.observeRequest(
                                    did,
                                ) catch |err| {
                                    std.debug.print(
                                        "DID inventory error: {s}\n",
                                        .{@errorName(err)},
                                    );

                                    return;
                                };

                                read_did_identifiers += 1;
                            }
                        }
                        if (service.service_id == 0x62) {
                            read_did_positive_responses += 1;

                            if (service.data.len < 2) {
                                malformed_read_did_positive_responses += 1;
                                continue;
                            }

                            const did =
                                (@as(u16, service.data[0]) << 8) |
                                @as(u16, service.data[1]);

                            did_inventory.observePositiveResponse(
                                did,
                                service.data[2..],
                            ) catch |err| {
                                std.debug.print(
                                    "DID response inventory error: {s}\n",
                                    .{@errorName(err)},
                                );

                                return;
                            };
                        }
                    },

                    .negative_response => {},
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

    var distinct_requested_dids: usize = 0;
    var distinct_response_dids: usize = 0;
    var did_count_mismatches: usize = 0;

    for (did_inventory.entries) |entry| {
        if (!entry.occupied) {
            continue;
        }

        if (entry.request_count > 0) {
            distinct_requested_dids += 1;
        }

        if (entry.positive_response_count > 0) {
            distinct_response_dids += 1;
        }

        if (entry.request_count !=
            entry.positive_response_count)
        {
            did_count_mismatches += 1;
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
        \\UDS messages: {}
        \\UDS parse rejected: {}
        \\negative responses: {}
        \\0x22 requests: {}
        \\0x22 identifiers requested: {}
        \\malformed 0x22 requests: {}
        \\multi-DID 0x22 requests: {}
        \\distinct requested DIDs: {}
        \\distinct response DIDs: {}
        \\DID request/response count mismatches: {}
        \\0x62 positive responses: {}
        \\malformed 0x62 positive responses: {}
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
            uds_messages,
            uds_parse_rejected,
            negative_responses,
            read_did_requests,
            read_did_identifiers,
            malformed_read_did_requests,
            multi_did_requests,
            distinct_requested_dids,
            distinct_response_dids,
            did_count_mismatches,
            read_did_positive_responses,
            malformed_read_did_positive_responses,
        },
    );

    std.debug.print(
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
    std.debug.print(
        "\nUDS service inventory:\n",
        .{},
    );

    for (uds_inventory.entries) |entry| {
        if (!entry.occupied) {
            continue;
        }

        switch (entry.kind) {
            .request_or_service => {
                std.debug.print(
                    "  {X:0>2} -> {X:0>2}: SID 0x{X:0>2}: {} messages\n",
                    .{
                        entry.source_address,
                        entry.destination_address,
                        entry.service_id,
                        entry.message_count,
                    },
                );
            },

            .positive_response => {
                std.debug.print(
                    "  {X:0>2} -> {X:0>2}: SID 0x{X:0>2} positive to 0x{X:0>2}: {} messages\n",
                    .{
                        entry.source_address,
                        entry.destination_address,
                        entry.service_id,
                        entry.request_service_id.?,
                        entry.message_count,
                    },
                );
            },

            .negative_response => {
                std.debug.print(
                    "  {X:0>2} -> {X:0>2}: SID 0x7F request 0x{X:0>2} code 0x{X:0>2}: {} messages\n",
                    .{
                        entry.source_address,
                        entry.destination_address,
                        entry.request_service_id.?,
                        entry.response_code.?,
                        entry.message_count,
                    },
                );
            },
        }
    }
    std.debug.print(
        "\nUDS 0x22 requested DID inventory:\n",
        .{},
    );

    for (did_inventory.entries) |entry| {
        if (!entry.occupied) {
            continue;
        }

        const value_state =
            if (entry.positive_response_count == 0)
                "no-response"
            else if (entry.positive_response_count == 1)
                "single-observation"
            else if (entry.value_changed or
            entry.value_min_length !=
                entry.value_max_length)
                "changing"
            else if (entry.comparison_limited)
                "comparison-limited"
            else
                "stable";

        std.debug.print(
            "  DID 0x{X:0>4}: {} requests, {} responses, value len {}..{}, {s}, printable-or-NUL {}/{}\n",
            .{
                entry.did,
                entry.request_count,
                entry.positive_response_count,
                entry.value_min_length,
                entry.value_max_length,
                value_state,
                entry.printable_or_nul_responses,
                entry.positive_response_count,
            },
        );
    }
}
