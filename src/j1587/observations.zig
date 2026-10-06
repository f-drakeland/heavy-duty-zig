const std = @import("std");
const parser = @import("parser.zig");
const diagnostics = @import("diagnostics.zig");

pub const SoftwareIdentification = struct {
    source_mid: u8,
    value: []const u8,
};

pub const Vin = struct {
    source_mid: u8,
    value: []const u8,
};

pub const Observation = union(enum) {
    software_identification: SoftwareIdentification,
    vin: Vin,
    component_identification: parser.ComponentIdentification,
    vehicle_distance: parser.TotalVehicleDistance,
    diagnostic_code: diagnostics.DiagnosticCode,
};

pub const DecodeError = parser.DecodeError || diagnostics.DecodeError;

pub const ObservationIterator = struct {
    source_mid: u8,
    pid: u8,
    data: []const u8,
    emitted: bool = false,
    diagnostic_codes: ?diagnostics.DiagnosticCodeIterator = null,

    pub fn next(
        self: *ObservationIterator,
    ) DecodeError!?Observation {
        if (self.pid == parser.pid_diagnostic_code_table) {
            if (self.diagnostic_codes == null) {
                self.diagnostic_codes = diagnostics.diagnosticCodes(
                    self.source_mid,
                    self.data,
                );
            }

            if (self.diagnostic_codes) |*codes| {
                const code =
                    (try codes.next()) orelse
                    return null;

                return .{
                    .diagnostic_code = code,
                };
            }

            unreachable;
        }

        if (self.emitted) {
            return null;
        }

        switch (self.pid) {
            parser.pid_software_identification => {
                self.emitted = true;

                return .{
                    .software_identification = .{
                        .source_mid = self.source_mid,
                        .value = parser.decodeSoftwareData(
                            self.data,
                        ),
                    },
                };
            },

            parser.pid_vin => {
                const vin = try parser.decodeVinData(
                    self.data,
                );

                self.emitted = true;

                return .{
                    .vin = .{
                        .source_mid = self.source_mid,
                        .value = vin,
                    },
                };
            },

            parser.pid_component_identification => {
                const component = try parser.decodeComponentData(
                    self.source_mid,
                    self.data,
                );

                self.emitted = true;

                return .{
                    .component_identification = component,
                };
            },

            parser.pid_total_vehicle_distance => {
                const distance = try parser.decodeTotalVehicleDistanceData(
                    self.source_mid,
                    self.data,
                );

                self.emitted = true;

                return .{
                    .vehicle_distance = distance,
                };
            },

            else => return error.UnsupportedPid,
        }
    }
};

pub fn observations(
    source_mid: u8,
    pid: u8,
    data: []const u8,
) ObservationIterator {
    return .{
        .source_mid = source_mid,
        .pid = pid,
        .data = data,
    };
}

test "observation types preserve source MID" {
    const observation = Observation{
        .software_identification = .{
            .source_mid = 128,
            .value = "SW-2.1",
        },
    };

    switch (observation) {
        .software_identification => |software| {
            try std.testing.expectEqual(
                @as(u8, 128),
                software.source_mid,
            );

            try std.testing.expectEqualStrings(
                "SW-2.1",
                software.value,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "PID 234 produces software identification observation" {
    var iterator = observations(
        128,
        parser.pid_software_identification,
        " SW-2.1\x00 ",
    );

    const observation =
        (try iterator.next()) orelse
        return error.TestUnexpectedResult;

    switch (observation) {
        .software_identification => |software| {
            try std.testing.expectEqual(
                @as(u8, 128),
                software.source_mid,
            );

            try std.testing.expectEqualStrings(
                "SW-2.1",
                software.value,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(
        @as(?Observation, null),
        try iterator.next(),
    );
}

test "PID 237 produces VIN observation" {
    var iterator = observations(
        128,
        parser.pid_vin,
        "1DEMO000000000001",
    );

    const observation =
        (try iterator.next()) orelse
        return error.TestUnexpectedResult;

    switch (observation) {
        .vin => |vin| {
            try std.testing.expectEqual(
                @as(u8, 128),
                vin.source_mid,
            );

            try std.testing.expectEqualStrings(
                "1DEMO000000000001",
                vin.value,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(
        @as(?Observation, null),
        try iterator.next(),
    );
}

test "PID 243 produces component identification observation" {
    var iterator = observations(
        137,
        parser.pid_component_identification,
        "\x89DEMO *ABS-4S2M*ABS-2099",
    );

    const observation =
        (try iterator.next()) orelse
        return error.TestUnexpectedResult;

    switch (observation) {
        .component_identification => |component| {
            try std.testing.expectEqual(
                @as(u8, 137),
                component.source_mid,
            );

            try std.testing.expectEqual(
                @as(u8, 137),
                component.component_mid,
            );

            try std.testing.expectEqualStrings(
                "DEMO",
                component.manufacturer,
            );

            try std.testing.expectEqualStrings(
                "ABS-4S2M",
                component.model_name,
            );

            try std.testing.expectEqualStrings(
                "ABS-2099",
                component.serial,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(
        @as(?Observation, null),
        try iterator.next(),
    );
}

test "PID 245 produces vehicle distance observation" {
    var iterator = observations(
        137,
        parser.pid_total_vehicle_distance,
        "\xe1\x00\x00\x00",
    );

    const observation =
        (try iterator.next()) orelse
        return error.TestUnexpectedResult;

    switch (observation) {
        .vehicle_distance => |distance| {
            try std.testing.expectEqual(
                @as(u8, 137),
                distance.source_mid,
            );

            try std.testing.expectEqual(
                @as(u32, 225),
                distance.raw_count,
            );

            try std.testing.expectApproxEqAbs(
                @as(f64, 22.5),
                distance.miles,
                0.0001,
            );

            try std.testing.expectApproxEqAbs(
                @as(f64, 36.225),
                distance.kilometers,
                0.0001,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(
        @as(?Observation, null),
        try iterator.next(),
    );
}

test "PID 194 produces multiple diagnostic observations" {
    var iterator = observations(
        128,
        parser.pid_diagnostic_code_table,
        "\x6e\x20" ++
            "\x6c\xa8\x01",
    );

    const first =
        (try iterator.next()) orelse
        return error.TestUnexpectedResult;

    switch (first) {
        .diagnostic_code => |code| {
            try std.testing.expectEqual(
                @as(u16, 110),
                code.identifier,
            );

            try std.testing.expectEqual(
                @as(u8, 0),
                code.fmi,
            );

            try std.testing.expectEqual(
                diagnostics.FaultStatus.active,
                code.status,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const second =
        (try iterator.next()) orelse
        return error.TestUnexpectedResult;

    switch (second) {
        .diagnostic_code => |code| {
            try std.testing.expectEqual(
                @as(u16, 108),
                code.identifier,
            );

            try std.testing.expectEqual(
                @as(u8, 8),
                code.fmi,
            );

            try std.testing.expectEqual(
                @as(?u8, 1),
                code.occurrence_count,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(
        @as(?Observation, null),
        try iterator.next(),
    );
}

test "empty PID 194 produces no observations" {
    var iterator = observations(
        128,
        parser.pid_diagnostic_code_table,
        "",
    );

    try std.testing.expectEqual(
        @as(?Observation, null),
        try iterator.next(),
    );
}
