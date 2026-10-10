pub const can = @import("can.zig");
pub const isotp = @import("isotp.zig");
pub const uds = @import("uds.zig");
pub const candump = @import("candump.zig");
pub const ddec_csv = @import("ddec_csv.zig");
const candump_audit = @import("candump_audit.zig");
const j1939_capture_audit = @import("j1939_capture_audit.zig");
pub const j1939 = @import("j1939.zig");
pub const correlation = @import("correlation.zig");
pub const j1708 = @import("j1708.zig");
pub const j1587 = @import("j1587.zig");
pub const frame_recovery = @import("frame_recovery.zig");
pub const capture_lineage = @import("capture_lineage.zig");
pub const capture_text = @import("capture_text.zig");
pub const capture_audit = @import("capture_audit.zig");
pub const capture_pipeline = @import("capture_pipeline.zig");

test {
    _ = can;
    _ = isotp;
    _ = uds;
    _ = candump;
    _ = ddec_csv;
    _ = candump_audit;
    _ = j1939_capture_audit;
    _ = j1939;
    _ = correlation;
    _ = j1708;
    _ = j1587;
    _ = frame_recovery;
    _ = capture_lineage;
    _ = capture_text;
    _ = capture_audit;
    _ = capture_pipeline;
}

test "authentic DDEC diagnostic traffic reaches ISO-TP parser" {
    const std = @import("std");

    const single_line =
        "133.028691,572,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18da00f1,data:,02,10,03,00,00,00,00,00,";

    const first_line =
        "135.396711,552,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,10,16,62,f1,95,00,02,56,";

    const flow_control_line =
        "135.397863,576,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18da00f1,data:,30,08,00,00,00,00,00,00,";

    const consecutive_line =
        "135.399007,560,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,21,00,01,52,15,00,00,61,";

    const single_record = switch (try ddec_csv.parseLine(single_line)) {
        .can => |record| record,
        else => return error.TestUnexpectedResult,
    };

    const single_can =
        try single_record.frame();

    const single =
        try isotp.parse(single_can.data());

    switch (single) {
        .single_frame => |frame| {
            try std.testing.expectEqual(
                @as(u8, 2),
                frame.declared_length,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{ 0x10, 0x03 },
                frame.payload,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const first_record = switch (try ddec_csv.parseLine(first_line)) {
        .can => |record| record,
        else => return error.TestUnexpectedResult,
    };

    const first_can =
        try first_record.frame();

    const first =
        try isotp.parse(first_can.data());

    switch (first) {
        .first_frame => |frame| {
            try std.testing.expectEqual(
                @as(u16, 0x16),
                frame.message_length,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{
                    0x62,
                    0xf1,
                    0x95,
                    0x00,
                    0x02,
                    0x56,
                },
                frame.data,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const flow_control_record = switch (try ddec_csv.parseLine(flow_control_line)) {
        .can => |record| record,
        else => return error.TestUnexpectedResult,
    };

    const flow_control_can =
        try flow_control_record.frame();

    const flow_control =
        try isotp.parse(
            flow_control_can.data(),
        );

    switch (flow_control) {
        .flow_control => |frame| {
            try std.testing.expectEqual(
                @as(u8, 0),
                frame.flow_status,
            );

            try std.testing.expectEqual(
                @as(u8, 8),
                frame.block_size,
            );

            try std.testing.expectEqual(
                @as(u8, 0),
                frame.separation_time,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const consecutive_record = switch (try ddec_csv.parseLine(consecutive_line)) {
        .can => |record| record,
        else => return error.TestUnexpectedResult,
    };

    const consecutive_can =
        try consecutive_record.frame();

    const consecutive =
        try isotp.parse(
            consecutive_can.data(),
        );

    switch (consecutive) {
        .consecutive_frame => |frame| {
            try std.testing.expectEqual(
                @as(u8, 1),
                frame.sequence_number,
            );

            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{
                    0x00,
                    0x01,
                    0x52,
                    0x15,
                    0x00,
                    0x00,
                    0x61,
                },
                frame.data,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "authentic DDEC diagnostic addresses route ISO-TP session" {
    const std = @import("std");

    const first_line =
        "135.396711,552,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,10,16,62,f1,95,00,02,56,";

    const flow_control_line =
        "135.397863,576,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18da00f1,data:,30,08,00,00,00,00,00,00,";

    const consecutive_line =
        "135.399007,560,On/Off,CAN (4a8),RX ch:1,Dlc:8,idx:,18daf100,data:,21,00,01,52,15,00,00,61,";

    const first_record = switch (try ddec_csv.parseLine(first_line)) {
        .can => |record| record,
        else => return error.TestUnexpectedResult,
    };

    const flow_control_record = switch (try ddec_csv.parseLine(flow_control_line)) {
        .can => |record| record,
        else => return error.TestUnexpectedResult,
    };

    const consecutive_record = switch (try ddec_csv.parseLine(consecutive_line)) {
        .can => |record| record,
        else => return error.TestUnexpectedResult,
    };

    const first_can =
        try first_record.frame();

    const flow_control_can =
        try flow_control_record.frame();

    const consecutive_can =
        try consecutive_record.frame();

    try std.testing.expectEqual(
        @as(u32, 0x18daf100),
        first_can.identifier(),
    );

    try std.testing.expectEqual(
        @as(u32, 0x18da00f1),
        flow_control_can.identifier(),
    );

    const first_source_address: u8 =
        @truncate(first_can.identifier());

    const first_destination_address: u8 =
        @truncate(first_can.identifier() >> 8);

    const flow_control_source_address: u8 =
        @truncate(flow_control_can.identifier());

    const flow_control_destination_address: u8 =
        @truncate(
            flow_control_can.identifier() >> 8,
        );

    const consecutive_source_address: u8 =
        @truncate(
            consecutive_can.identifier(),
        );

    const consecutive_destination_address: u8 =
        @truncate(
            consecutive_can.identifier() >> 8,
        );

    try std.testing.expectEqual(
        @as(u8, 0x00),
        first_source_address,
    );

    try std.testing.expectEqual(
        @as(u8, 0xf1),
        first_destination_address,
    );

    try std.testing.expectEqual(
        @as(u8, 0xf1),
        flow_control_source_address,
    );

    try std.testing.expectEqual(
        @as(u8, 0x00),
        flow_control_destination_address,
    );

    var router =
        isotp.SessionRouter(4, 64){};

    const first_event =
        try router.push(
            first_source_address,
            first_destination_address,
            try isotp.parse(
                first_can.data(),
            ),
        );

    try std.testing.expect(
        first_event == .in_progress,
    );

    const flow_control_event =
        try router.push(
            flow_control_source_address,
            flow_control_destination_address,
            try isotp.parse(
                flow_control_can.data(),
            ),
        );

    switch (flow_control_event) {
        .flow_control => |flow_control| {
            try std.testing.expect(
                flow_control
                    .matched_active_transfer,
            );

            try std.testing.expectEqual(
                @as(u8, 8),
                flow_control
                    .flow_control
                    .block_size,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const consecutive_event =
        try router.push(
            consecutive_source_address,
            consecutive_destination_address,
            try isotp.parse(
                consecutive_can.data(),
            ),
        );

    try std.testing.expect(
        consecutive_event == .in_progress,
    );
}

test "logger text reaches typed J1587 observation" {
    const std = @import("std");

    var byte_storage: [64]u8 = undefined;

    const record = try capture_text.parseLine(
        "STATUS_OK synthetic [128, 234, 6, 83, 87, 45, 50, 46, 49, 40]",
        &byte_storage,
    );

    var scratch: [65]frame_recovery.ScratchState = undefined;

    const result = try frame_recovery.recover(
        record.bytes,
        &scratch,
    );

    switch (result) {
        .recovered => |recovered_frames| {
            var frames = recovered_frames;

            const frame = frames.next().?;

            var decoder = j1587.Decoder.init();

            var cursor = try j1587.frame_cursor.FrameCursor.init(
                frame,
                &decoder,
            );

            const event = (try cursor.next()).?;

            switch (event) {
                .observation => |observation| {
                    switch (observation) {
                        .software_identification => |software| {
                            try std.testing.expectEqualSlices(
                                u8,
                                "SW-2.1",
                                software.value,
                            );
                        },
                        else => return error.TestUnexpectedResult,
                    }
                },
                else => return error.TestUnexpectedResult,
            }

            try std.testing.expect(
                (try cursor.next()) == null,
            );

            try std.testing.expect(
                frames.next() == null,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}
