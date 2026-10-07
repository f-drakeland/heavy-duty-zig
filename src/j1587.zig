const std = @import("std");
const parser = @import("j1587/parser.zig");
const observations_module = @import("j1587/observations.zig");
const decoder_module = @import("j1587/decoder.zig");
pub const structure = @import("j1587/structure.zig");
pub const parameters = @import("j1587/parameters.zig");
pub const frame_cursor = @import("j1587/frame_cursor.zig");

// PID constants
pub const pid_multisection = parser.pid_multisection;
pub const pid_diagnostic_code_table = parser.pid_diagnostic_code_table;
pub const pid_software_identification = parser.pid_software_identification;
pub const pid_vin = parser.pid_vin;
pub const pid_component_identification = parser.pid_component_identification;
pub const pid_total_vehicle_distance = parser.pid_total_vehicle_distance;

// Core parser types
pub const DecodeError = parser.DecodeError;
pub const Message = parser.Message;
pub const ComponentIdentification = parser.ComponentIdentification;
pub const TotalVehicleDistance = parser.TotalVehicleDistance;

// Core parser functions
pub const parseMessage = parser.parseMessage;
pub const decodeComponentData = parser.decodeComponentData;
pub const decodeSoftwareData = parser.decodeSoftwareData;
pub const decodeVinData = parser.decodeVinData;
pub const decodeTotalVehicleDistanceData = parser.decodeTotalVehicleDistanceData;

// Multisection transport
pub const multisection = @import("j1587/multisection.zig");

// Diagnostics
pub const diagnostics = @import("j1587/diagnostics.zig");

pub const IdentifierKind = diagnostics.IdentifierKind;
pub const FaultStatus = diagnostics.FaultStatus;
pub const DiagnosticCode = diagnostics.DiagnosticCode;
pub const DiagnosticCodeIterator = diagnostics.DiagnosticCodeIterator;

pub const diagnosticCodes = diagnostics.diagnosticCodes;

// Observations
pub const SoftwareIdentification = observations_module.SoftwareIdentification;
pub const Vin = observations_module.Vin;
pub const Observation = observations_module.Observation;
pub const ObservationIterator = observations_module.ObservationIterator;

pub const observations = observations_module.observations;

pub const Decoder = decoder_module.Decoder;
pub const DecoderError = decoder_module.DecodeError;
pub const PushResult = decoder_module.PushResult;
pub const UnsupportedParameter = decoder_module.UnsupportedParameter;

test {
    _ = parser;
    _ = multisection;
    _ = diagnostics;
    _ = observations_module;
    _ = decoder_module;
    _ = structure;
    _ = parameters;
    _ = frame_cursor;
}

test "parse J1587 PID 194 message into diagnostic code" {
    const message =
        "\x80\xc2\x02\x6e\x20";

    const parsed =
        try parseMessage(message);

    try std.testing.expectEqual(
        @as(u8, 128),
        parsed.source_mid,
    );

    try std.testing.expectEqual(
        pid_diagnostic_code_table,
        parsed.pid,
    );

    var codes =
        diagnosticCodes(
            parsed.source_mid,
            parsed.data,
        );

    const code =
        (try codes.next()) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        IdentifierKind.pid,
        code.identifier_kind,
    );

    try std.testing.expectEqual(
        @as(u16, 110),
        code.identifier,
    );

    try std.testing.expectEqual(
        @as(u8, 0),
        code.fmi,
    );

    try std.testing.expectEqual(
        FaultStatus.active,
        code.status,
    );

    try std.testing.expectEqual(
        @as(?DiagnosticCode, null),
        try codes.next(),
    );
}

test "reassemble multisection PID 194 and decode diagnostic codes" {
    const first =
        "\x80\xc0\x06\xc2\x10\x05\x6e\x20\x6c";

    const second =
        "\x80\xc0\x04\xc2\x11\xa8\x01";

    var bank = multisection.Bank.init();

    try std.testing.expectEqual(
        multisection.PushResult.pending,
        try bank.push(first),
    );

    const result = try bank.push(second);

    switch (result) {
        .pending => return error.TestUnexpectedResult,

        .complete => |parameter| {
            try std.testing.expectEqual(
                pid_diagnostic_code_table,
                parameter.pid,
            );

            var codes = diagnosticCodes(
                parameter.source_mid,
                parameter.data,
            );

            const first_code =
                (try codes.next()) orelse
                return error.TestUnexpectedResult;

            try std.testing.expectEqual(
                IdentifierKind.pid,
                first_code.identifier_kind,
            );

            try std.testing.expectEqual(
                @as(u16, 110),
                first_code.identifier,
            );

            try std.testing.expectEqual(
                @as(u8, 0),
                first_code.fmi,
            );

            const second_code =
                (try codes.next()) orelse
                return error.TestUnexpectedResult;

            try std.testing.expectEqual(
                IdentifierKind.pid,
                second_code.identifier_kind,
            );

            try std.testing.expectEqual(
                @as(u16, 108),
                second_code.identifier,
            );

            try std.testing.expectEqual(
                @as(u8, 8),
                second_code.fmi,
            );

            try std.testing.expectEqual(
                @as(?u8, 1),
                second_code.occurrence_count,
            );

            try std.testing.expectEqual(
                @as(?DiagnosticCode, null),
                try codes.next(),
            );
        },
    }
}
