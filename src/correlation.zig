const std = @import("std");

const j1587 = @import("j1587.zig");
const j1939 = @import("j1939.zig");

const can = @import("can.zig");
const capture_text = @import("capture_text.zig");
const frame_recovery = @import("frame_recovery.zig");

/// Identifies the protocol address from which evidence was observed.
///
/// This is capture-local network evidence. It is not a permanent ECU,
/// controller, component, or physical-device identity.
pub const EndpointKey = union(enum) {
    j1587_mid: u8,
    j1939_source_address: u8,

    pub fn eql(
        self: EndpointKey,
        other: EndpointKey,
    ) bool {
        return switch (self) {
            .j1587_mid => |mid| switch (other) {
                .j1587_mid => |other_mid| mid == other_mid,

                else => false,
            },

            .j1939_source_address => |source_address| switch (other) {
                .j1939_source_address => |other_source_address| source_address == other_source_address,

                else => false,
            },
        };
    }
};

/// Typed protocol evidence associated with an observed protocol endpoint.
///
/// Any slices contained in the underlying observation remain borrowed from
/// their original input storage. This type does not extend their lifetime.
pub const Evidence = union(enum) {
    j1587: j1587.Observation,
    j1939: j1939.Observation,
};

pub const EndpointObservation = struct {
    endpoint: EndpointKey,
    evidence: Evidence,
};
pub const IdentityStorageError = error{
    IdentityCapacityExceeded,
};

fn OwnedTextFields(
    comptime capacity: usize,
    comptime field_count: usize,
) type {
    if (capacity == 0) {
        @compileError(
            "owned text capacity must be greater than zero",
        );
    }

    if (field_count == 0) {
        @compileError(
            "owned text field count must be greater than zero",
        );
    }

    return struct {
        const Self = @This();

        storage: [capacity]u8 = undefined,
        offsets: [field_count + 1]usize =
            @splat(0),
        len: usize = 0,

        pub fn fromSlices(
            fields: [field_count][]const u8,
        ) IdentityStorageError!Self {
            var result: Self = .{};

            for (fields, 0..) |field_bytes, index| {
                if (field_bytes.len > capacity - result.len) {
                    return error.IdentityCapacityExceeded;
                }

                @memcpy(
                    result.storage[result.len .. result.len + field_bytes.len],
                    field_bytes,
                );

                result.len += field_bytes.len;
                result.offsets[index + 1] =
                    result.len;
            }

            return result;
        }

        pub fn eql(
            self: *const Self,
            other: *const Self,
        ) bool {
            if (self.len != other.len) {
                return false;
            }

            if (!std.mem.eql(
                u8,
                self.storage[0..self.len],
                other.storage[0..other.len],
            )) {
                return false;
            }

            return std.mem.eql(
                usize,
                self.offsets[0..],
                other.offsets[0..],
            );
        }

        pub fn field(
            self: *const Self,
            comptime index: usize,
        ) []const u8 {
            if (index >= field_count) {
                @compileError(
                    "owned text field index out of bounds",
                );
            }

            return self.storage[self.offsets[index]..self.offsets[index + 1]];
        }
    };
}

/// Durable copy of identity-bearing protocol evidence.
///
/// This preserves what a protocol endpoint reported. It does not establish
/// permanent controller, component, vehicle, or physical ECU identity.
pub fn OwnedIdentityObservation(
    comptime text_capacity: usize,
) type {
    const Text1 =
        OwnedTextFields(text_capacity, 1);

    const Text3 =
        OwnedTextFields(text_capacity, 3);

    const Text4 =
        OwnedTextFields(text_capacity, 4);

    return struct {
        const Self = @This();

        pub const J1587ComponentIdentification = struct {
            component_mid: u8,
            fields: Text3,
        };

        pub const J1939AddressClaim = struct {
            delivery: j1939.MessageDelivery,
            name: j1939.address_claim.Name,
        };

        pub const J1939ComponentIdentification = struct {
            delivery: j1939.MessageDelivery,
            fields: Text4,
        };

        pub const IdentityEvidence = union(enum) {
            j1587_software_identification: Text1,
            j1587_vin: Text1,
            j1587_component_identification: J1587ComponentIdentification,

            j1939_address_claim: J1939AddressClaim,

            j1939_component_identification: J1939ComponentIdentification,
        };

        endpoint: EndpointKey,
        evidence: IdentityEvidence,
        pub fn eqlExact(
            self: *const Self,
            other: *const Self,
        ) bool {
            if (!self.endpoint.eql(other.endpoint)) {
                return false;
            }

            return switch (self.evidence) {
                .j1587_software_identification => |value| switch (other.evidence) {
                    .j1587_software_identification => |other_value| value.eql(&other_value),

                    else => false,
                },

                .j1587_vin => |value| switch (other.evidence) {
                    .j1587_vin => |other_value| value.eql(&other_value),

                    else => false,
                },

                .j1587_component_identification => |value| switch (other.evidence) {
                    .j1587_component_identification => |other_value| value.component_mid == other_value.component_mid and
                        value.fields.eql(&other_value.fields),

                    else => false,
                },

                .j1939_address_claim => |value| switch (other.evidence) {
                    .j1939_address_claim => |other_value| value.delivery == other_value.delivery and
                        value.name.raw == other_value.name.raw,

                    else => false,
                },

                .j1939_component_identification => |value| switch (other.evidence) {
                    .j1939_component_identification => |other_value| value.delivery == other_value.delivery and
                        value.fields.eql(&other_value.fields),

                    else => false,
                },
            };
        }

        pub fn fromEndpointObservation(
            observation: EndpointObservation,
        ) IdentityStorageError!?Self {
            return switch (observation.evidence) {
                .j1587 => |evidence| switch (evidence) {
                    .software_identification => |value| .{
                        .endpoint = observation.endpoint,
                        .evidence = .{
                            .j1587_software_identification = try Text1.fromSlices(.{
                                value.value,
                            }),
                        },
                    },

                    .vin => |value| .{
                        .endpoint = observation.endpoint,
                        .evidence = .{
                            .j1587_vin = try Text1.fromSlices(.{
                                value.value,
                            }),
                        },
                    },

                    .component_identification => |value| .{
                        .endpoint = observation.endpoint,
                        .evidence = .{
                            .j1587_component_identification = .{
                                .component_mid = value.component_mid,
                                .fields = try Text3.fromSlices(.{
                                    value.manufacturer,
                                    value.model_name,
                                    value.serial,
                                }),
                            },
                        },
                    },

                    .vehicle_distance,
                    .road_speed,
                    .accelerator_pedal_position,
                    .engine_load,
                    .engine_speed,
                    .diagnostic_code,
                    => null,
                },

                .j1939 => |evidence| switch (evidence) {
                    .address_claim => |value| .{
                        .endpoint = observation.endpoint,
                        .evidence = .{
                            .j1939_address_claim = .{
                                .delivery = value.delivery,
                                .name = value.name,
                            },
                        },
                    },

                    .component_identification => |value| .{
                        .endpoint = observation.endpoint,
                        .evidence = .{
                            .j1939_component_identification = .{
                                .delivery = value.delivery,
                                .fields = try Text4.fromSlices(.{
                                    value.make,
                                    value.model,
                                    value.serial_number,
                                    value.unit_number,
                                }),
                            },
                        },
                    },

                    .eec1_engine_speed,
                    .dm1_lamps,
                    .dm1_diagnostic_trouble_code,
                    => null,
                },
            };
        }
    };
}

pub const IdentityObserveResult = enum {
    non_identity,
    new_evidence,
    existing_evidence,
};

pub const IdentityInventoryError =
    IdentityStorageError ||
    error{
        IdentityEvidenceCapacityExceeded,
    };

/// Bounded capture-local inventory of distinct identity-bearing evidence.
///
/// Exact repeated evidence increments an occurrence count. Conflicting or
/// otherwise distinct evidence is preserved separately. No observation is
/// promoted to a permanent controller, component, vehicle, or physical ECU
/// identity.
pub fn IdentityEvidenceInventory(
    comptime evidence_capacity: usize,
    comptime text_capacity: usize,
) type {
    if (evidence_capacity == 0) {
        @compileError(
            "identity evidence capacity must be greater than zero",
        );
    }

    const Owned =
        OwnedIdentityObservation(text_capacity);

    return struct {
        const Self = @This();

        pub const EvidenceView = struct {
            observation: *const Owned,
            occurrence_count: usize,
        };

        const Slot = struct {
            occupied: bool = false,
            observation: Owned = undefined,
            occurrence_count: usize = 0,
        };

        slots: [evidence_capacity]Slot =
            @splat(.{}),

        evidence_count: usize = 0,

        pub fn observe(
            self: *Self,
            observation: EndpointObservation,
        ) IdentityInventoryError!IdentityObserveResult {
            const owned =
                (try Owned.fromEndpointObservation(
                    observation,
                )) orelse
                return .non_identity;

            if (self.findExact(&owned)) |slot| {
                slot.occurrence_count += 1;

                return .existing_evidence;
            }

            const slot =
                self.findFreeSlot() orelse
                return error.IdentityEvidenceCapacityExceeded;

            slot.* = .{
                .occupied = true,
                .observation = owned,
                .occurrence_count = 1,
            };

            self.evidence_count += 1;

            return .new_evidence;
        }

        pub fn count(
            self: *const Self,
        ) usize {
            return self.evidence_count;
        }

        pub fn evidenceCountForEndpoint(
            self: *const Self,
            key: EndpointKey,
        ) usize {
            var count_for_endpoint: usize = 0;

            for (&self.slots) |*slot| {
                if (slot.occupied and
                    slot.observation.endpoint.eql(key))
                {
                    count_for_endpoint += 1;
                }
            }

            return count_for_endpoint;
        }

        pub fn evidenceAt(
            self: *const Self,
            index: usize,
        ) ?EvidenceView {
            var observed_index: usize = 0;

            for (&self.slots) |*slot| {
                if (!slot.occupied) {
                    continue;
                }

                if (observed_index == index) {
                    return .{
                        .observation = &slot.observation,
                        .occurrence_count = slot.occurrence_count,
                    };
                }

                observed_index += 1;
            }

            return null;
        }

        pub fn evidenceForEndpointAt(
            self: *const Self,
            key: EndpointKey,
            index: usize,
        ) ?EvidenceView {
            var observed_index: usize = 0;

            for (&self.slots) |*slot| {
                if (!slot.occupied or
                    !slot.observation.endpoint.eql(key))
                {
                    continue;
                }

                if (observed_index == index) {
                    return .{
                        .observation = &slot.observation,
                        .occurrence_count = slot.occurrence_count,
                    };
                }

                observed_index += 1;
            }

            return null;
        }

        fn findExact(
            self: *Self,
            observation: *const Owned,
        ) ?*Slot {
            for (&self.slots) |*slot| {
                if (slot.occupied and
                    slot.observation.eqlExact(
                        observation,
                    ))
                {
                    return slot;
                }
            }

            return null;
        }

        fn findFreeSlot(
            self: *Self,
        ) ?*Slot {
            for (&self.slots) |*slot| {
                if (!slot.occupied) {
                    return slot;
                }
            }

            return null;
        }
    };
}
pub const EndpointSummary = struct {
    key: EndpointKey,
    observation_count: usize,
};

pub const InventoryObserveResult = enum {
    new_endpoint,
    existing_endpoint,
};

pub const InventoryError = error{
    EndpointCapacityExceeded,
};

/// Capture-local inventory of observed protocol endpoints.
///
/// This inventory retains endpoint keys and observation counts only.
/// It does not retain borrowed protocol evidence or imply permanent
/// controller or physical ECU identity.
pub fn EndpointInventory(
    comptime capacity: usize,
) type {
    if (capacity == 0) {
        @compileError(
            "endpoint inventory capacity must be greater than zero",
        );
    }

    return struct {
        const Self = @This();

        const Slot = struct {
            occupied: bool = false,
            key: EndpointKey = .{
                .j1587_mid = 0,
            },
            observation_count: usize = 0,
        };

        slots: [capacity]Slot =
            @splat(.{}),

        endpoint_count: usize = 0,

        pub fn observe(
            self: *Self,
            observation: EndpointObservation,
        ) InventoryError!InventoryObserveResult {
            if (self.findSlot(observation.endpoint)) |slot| {
                slot.observation_count += 1;

                return .existing_endpoint;
            }

            const slot =
                self.findFreeSlot() orelse
                return error.EndpointCapacityExceeded;

            slot.* = .{
                .occupied = true,
                .key = observation.endpoint,
                .observation_count = 1,
            };

            self.endpoint_count += 1;

            return .new_endpoint;
        }

        pub fn count(
            self: *const Self,
        ) usize {
            return self.endpoint_count;
        }

        pub fn endpointAt(
            self: *const Self,
            index: usize,
        ) ?EndpointSummary {
            var observed_index: usize = 0;

            for (&self.slots) |*slot| {
                if (!slot.occupied) {
                    continue;
                }

                if (observed_index == index) {
                    return .{
                        .key = slot.key,
                        .observation_count = slot.observation_count,
                    };
                }

                observed_index += 1;
            }

            return null;
        }

        pub fn observationCount(
            self: *const Self,
            key: EndpointKey,
        ) ?usize {
            for (&self.slots) |*slot| {
                if (slot.occupied and
                    slot.key.eql(key))
                {
                    return slot.observation_count;
                }
            }

            return null;
        }

        fn findSlot(
            self: *Self,
            key: EndpointKey,
        ) ?*Slot {
            for (&self.slots) |*slot| {
                if (slot.occupied and
                    slot.key.eql(key))
                {
                    return slot;
                }
            }

            return null;
        }

        fn findFreeSlot(
            self: *Self,
        ) ?*Slot {
            for (&self.slots) |*slot| {
                if (!slot.occupied) {
                    return slot;
                }
            }

            return null;
        }
    };
}

pub fn fromJ1587(
    observation: j1587.Observation,
) EndpointObservation {
    const source_mid = switch (observation) {
        .software_identification => |value| value.source_mid,

        .vin => |value| value.source_mid,

        .component_identification => |value| value.source_mid,

        .vehicle_distance => |value| value.source_mid,

        .road_speed => |value| value.source_mid,

        .accelerator_pedal_position => |value| value.source_mid,

        .engine_load => |value| value.source_mid,

        .engine_speed => |value| value.source_mid,

        .diagnostic_code => |value| value.source_mid,
    };

    return .{
        .endpoint = .{
            .j1587_mid = source_mid,
        },
        .evidence = .{
            .j1587 = observation,
        },
    };
}

pub fn fromJ1939(
    observation: j1939.Observation,
) EndpointObservation {
    const source_address = switch (observation) {
        .component_identification => |value| value.source_address,

        .address_claim => |value| value.source_address,

        .eec1_engine_speed => |value| value.source_address,

        .dm1_lamps => |value| value.source_address,

        .dm1_diagnostic_trouble_code => |value| value.source_address,
    };

    return .{
        .endpoint = .{
            .j1939_source_address = source_address,
        },
        .evidence = .{
            .j1939 = observation,
        },
    };
}

test "J1587 observation retains MID endpoint" {
    const observation: j1587.Observation = .{
        .engine_speed = .{
            .source_mid = 128,
            .raw_count = 2400,
            .rpm = 600.0,
        },
    };

    const correlated =
        fromJ1587(observation);

    switch (correlated.endpoint) {
        .j1587_mid => |mid| {
            try std.testing.expectEqual(
                @as(u8, 128),
                mid,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "J1939 observations from same source share endpoint key" {
    const engine_speed: j1939.Observation = .{
        .eec1_engine_speed = .{
            .source_address = 0x00,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    };

    const component: j1939.Observation = .{
        .component_identification = .{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "DTDSC",
            .model = "471N10",
            .serial_number = "S0066951",
            .unit_number = "611035",
        },
    };

    const first =
        fromJ1939(engine_speed);

    const second =
        fromJ1939(component);

    try std.testing.expect(
        first.endpoint.eql(second.endpoint),
    );
}

test "same numeric address across protocols is not same endpoint" {
    const j1587_endpoint: EndpointKey = .{
        .j1587_mid = 128,
    };

    const j1939_endpoint: EndpointKey = .{
        .j1939_source_address = 128,
    };

    try std.testing.expect(
        !j1587_endpoint.eql(j1939_endpoint),
    );
}

test "decoded J1587 observation becomes endpoint observation" {
    var byte_storage: [64]u8 = undefined;

    const record = try capture_text.parseLine(
        "STATUS_OK synthetic [128, 234, 6, 83, 87, 45, 50, 46, 49, 40]",
        &byte_storage,
    );

    var scratch: [65]frame_recovery.ScratchState = undefined;

    const recovery = try frame_recovery.recover(
        record.bytes,
        &scratch,
    );

    switch (recovery) {
        .recovered => |recovered_frames| {
            var frames = recovered_frames;

            const frame =
                frames.next() orelse
                return error.TestUnexpectedResult;

            var decoder = j1587.Decoder.init();

            var cursor =
                try j1587.frame_cursor.FrameCursor.init(
                    frame,
                    &decoder,
                );

            const event =
                (try cursor.next()).?;

            const observation = switch (event) {
                .observation => |observation| observation,

                else => return error.TestUnexpectedResult,
            };

            const endpoint_observation =
                fromJ1587(observation);

            switch (endpoint_observation.endpoint) {
                .j1587_mid => |mid| {
                    try std.testing.expectEqual(
                        @as(u8, 128),
                        mid,
                    );
                },

                else => return error.TestUnexpectedResult,
            }

            switch (endpoint_observation.evidence) {
                .j1587 => |evidence| {
                    switch (evidence) {
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
        },

        else => return error.TestUnexpectedResult,
    }
}

test "authentic J1939 address claim becomes endpoint observation" {
    const payload = [_]u8{
        0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    const can_frame =
        try can.FrameView.fromParts(
            0x18eefff9,
            .extended,
            .data,
            8,
            &payload,
        );

    const frame =
        try j1939.FrameView.fromCanFrame(
            can_frame,
        );

    const message =
        j1939.MessageView.fromSingleFrame(
            frame,
        );

    var cursor =
        try j1939.MessageCursor.init(
            message,
        );

    const event =
        (try cursor.next()).?;

    const observation = switch (event) {
        .observation => |observation| observation,

        else => return error.TestUnexpectedResult,
    };

    const endpoint_observation =
        fromJ1939(observation);

    switch (endpoint_observation.endpoint) {
        .j1939_source_address => |source_address| {
            try std.testing.expectEqual(
                @as(u8, 0xf9),
                source_address,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    switch (endpoint_observation.evidence) {
        .j1939 => |evidence| {
            switch (evidence) {
                .address_claim => |claim| {
                    try std.testing.expectEqual(
                        @as(u64, 0x0000000000010000),
                        claim.name.raw,
                    );

                    try std.testing.expectEqual(
                        @as(u32, 65536),
                        claim.name.identityNumber(),
                    );
                },

                else => return error.TestUnexpectedResult,
            }
        },

        else => return error.TestUnexpectedResult,
    }
}

test "inventory groups observations from same J1939 endpoint" {
    const first = fromJ1939(.{
        .eec1_engine_speed = .{
            .source_address = 0x00,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    });

    const second = fromJ1939(.{
        .component_identification = .{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "DTDSC",
            .model = "471N10",
            .serial_number = "S0066951",
            .unit_number = "611035",
        },
    });

    var inventory = EndpointInventory(4){};

    try std.testing.expectEqual(
        InventoryObserveResult.new_endpoint,
        try inventory.observe(first),
    );

    try std.testing.expectEqual(
        InventoryObserveResult.existing_endpoint,
        try inventory.observe(second),
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        inventory.count(),
    );

    try std.testing.expectEqual(
        @as(?usize, 2),
        inventory.observationCount(.{
            .j1939_source_address = 0x00,
        }),
    );
}

test "inventory keeps same numeric address separate across protocols" {
    const j1587_observation = fromJ1587(.{
        .engine_speed = .{
            .source_mid = 128,
            .raw_count = 2400,
            .rpm = 600.0,
        },
    });

    const j1939_observation = fromJ1939(.{
        .eec1_engine_speed = .{
            .source_address = 128,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    });

    var inventory = EndpointInventory(4){};

    _ = try inventory.observe(
        j1587_observation,
    );

    _ = try inventory.observe(
        j1939_observation,
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        inventory.count(),
    );

    try std.testing.expectEqual(
        @as(?usize, 1),
        inventory.observationCount(.{
            .j1587_mid = 128,
        }),
    );

    try std.testing.expectEqual(
        @as(?usize, 1),
        inventory.observationCount(.{
            .j1939_source_address = 128,
        }),
    );

    const first_endpoint =
        inventory.endpointAt(0) orelse
        return error.TestUnexpectedResult;

    const second_endpoint =
        inventory.endpointAt(1) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(
        first_endpoint.key.eql(.{
            .j1587_mid = 128,
        }),
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        first_endpoint.observation_count,
    );

    try std.testing.expect(
        second_endpoint.key.eql(.{
            .j1939_source_address = 128,
        }),
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        second_endpoint.observation_count,
    );

    try std.testing.expect(
        inventory.endpointAt(2) == null,
    );
}

test "inventory reports endpoint capacity exhaustion" {
    const first = fromJ1939(.{
        .eec1_engine_speed = .{
            .source_address = 0x00,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    });

    const second = fromJ1939(.{
        .eec1_engine_speed = .{
            .source_address = 0x01,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    });

    var inventory = EndpointInventory(1){};

    _ = try inventory.observe(first);

    try std.testing.expectError(
        error.EndpointCapacityExceeded,
        inventory.observe(second),
    );
}

test "owned identity observation copies borrowed J1587 software evidence" {
    var software_bytes = [_]u8{
        'S', 'W', '-', '2', '.', '1',
    };

    const observation = fromJ1587(.{
        .software_identification = .{
            .source_mid = 128,
            .value = &software_bytes,
        },
    });

    const Owned =
        OwnedIdentityObservation(16);

    const owned =
        (try Owned.fromEndpointObservation(
            observation,
        )) orelse
        return error.TestUnexpectedResult;

    software_bytes[0] = 'X';

    switch (owned.evidence) {
        .j1587_software_identification => |software| {
            try std.testing.expectEqualStrings(
                "SW-2.1",
                software.field(0),
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "owned J1939 component evidence preserves field boundaries" {
    const observation = fromJ1939(.{
        .component_identification = .{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "DTDSC",
            .model = "471N10",
            .serial_number = "S0066951",
            .unit_number = "611035",
        },
    });

    const Owned =
        OwnedIdentityObservation(32);

    const owned =
        (try Owned.fromEndpointObservation(
            observation,
        )) orelse
        return error.TestUnexpectedResult;

    switch (owned.evidence) {
        .j1939_component_identification => |component| {
            try std.testing.expectEqualStrings(
                "DTDSC",
                component.fields.field(0),
            );

            try std.testing.expectEqualStrings(
                "471N10",
                component.fields.field(1),
            );

            try std.testing.expectEqualStrings(
                "S0066951",
                component.fields.field(2),
            );

            try std.testing.expectEqualStrings(
                "611035",
                component.fields.field(3),
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "owned identity evidence reports capacity exhaustion" {
    const observation = fromJ1587(.{
        .software_identification = .{
            .source_mid = 128,
            .value = "SW-2.1",
        },
    });

    const Owned =
        OwnedIdentityObservation(4);

    try std.testing.expectError(
        error.IdentityCapacityExceeded,
        Owned.fromEndpointObservation(
            observation,
        ),
    );
}

test "non-identity observation produces no owned identity evidence" {
    const observation = fromJ1939(.{
        .eec1_engine_speed = .{
            .source_address = 0x00,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    });

    const Owned =
        OwnedIdentityObservation(32);

    try std.testing.expect(
        (try Owned.fromEndpointObservation(
            observation,
        )) == null,
    );
}

test "owned identity exact equality compares copied contents" {
    const Owned =
        OwnedIdentityObservation(32);

    const first =
        (try Owned.fromEndpointObservation(
            fromJ1587(.{
                .software_identification = .{
                    .source_mid = 128,
                    .value = "SW-2.1",
                },
            }),
        )) orelse
        return error.TestUnexpectedResult;

    const second =
        (try Owned.fromEndpointObservation(
            fromJ1587(.{
                .software_identification = .{
                    .source_mid = 128,
                    .value = "SW-2.1",
                },
            }),
        )) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(
        first.eqlExact(&second),
    );
}

test "owned identity exact equality includes endpoint" {
    const Owned =
        OwnedIdentityObservation(32);

    const first =
        (try Owned.fromEndpointObservation(
            fromJ1587(.{
                .software_identification = .{
                    .source_mid = 128,
                    .value = "SW-2.1",
                },
            }),
        )) orelse
        return error.TestUnexpectedResult;

    const second =
        (try Owned.fromEndpointObservation(
            fromJ1587(.{
                .software_identification = .{
                    .source_mid = 129,
                    .value = "SW-2.1",
                },
            }),
        )) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(
        !first.eqlExact(&second),
    );
}

test "owned identity exact equality preserves component field boundaries" {
    const Owned =
        OwnedIdentityObservation(32);

    const first =
        (try Owned.fromEndpointObservation(
            fromJ1939(.{
                .component_identification = .{
                    .source_address = 0x00,
                    .delivery = .rts_cts,
                    .make = "AB",
                    .model = "C",
                    .serial_number = "D",
                    .unit_number = "E",
                },
            }),
        )) orelse
        return error.TestUnexpectedResult;

    const second =
        (try Owned.fromEndpointObservation(
            fromJ1939(.{
                .component_identification = .{
                    .source_address = 0x00,
                    .delivery = .rts_cts,
                    .make = "A",
                    .model = "BC",
                    .serial_number = "D",
                    .unit_number = "E",
                },
            }),
        )) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(
        !first.eqlExact(&second),
    );
}

test "owned identity exact equality includes delivery evidence" {
    const Owned =
        OwnedIdentityObservation(32);

    const first =
        (try Owned.fromEndpointObservation(
            fromJ1939(.{
                .component_identification = .{
                    .source_address = 0x00,
                    .delivery = .bam,
                    .make = "DTDSC",
                    .model = "471N10",
                    .serial_number = "S0066951",
                    .unit_number = "611035",
                },
            }),
        )) orelse
        return error.TestUnexpectedResult;

    const second =
        (try Owned.fromEndpointObservation(
            fromJ1939(.{
                .component_identification = .{
                    .source_address = 0x00,
                    .delivery = .rts_cts,
                    .make = "DTDSC",
                    .model = "471N10",
                    .serial_number = "S0066951",
                    .unit_number = "611035",
                },
            }),
        )) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(
        !first.eqlExact(&second),
    );
}

test "identity inventory counts repeated exact evidence" {
    const observation = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x1003030000400064,
            },
        },
    });

    var inventory =
        IdentityEvidenceInventory(4, 32){};

    try std.testing.expectEqual(
        IdentityObserveResult.new_evidence,
        try inventory.observe(observation),
    );

    try std.testing.expectEqual(
        IdentityObserveResult.existing_evidence,
        try inventory.observe(observation),
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        inventory.count(),
    );

    const evidence =
        inventory.evidenceAt(0) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(usize, 2),
        evidence.occurrence_count,
    );

    try std.testing.expect(
        inventory.evidenceAt(1) == null,
    );
}

test "identity inventory preserves conflicting evidence from same endpoint" {
    const first = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x1003030000400064,
            },
        },
    });

    const second = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x2003030000400064,
            },
        },
    });

    var inventory =
        IdentityEvidenceInventory(4, 32){};

    try std.testing.expectEqual(
        IdentityObserveResult.new_evidence,
        try inventory.observe(first),
    );

    try std.testing.expectEqual(
        IdentityObserveResult.new_evidence,
        try inventory.observe(second),
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        inventory.count(),
    );

    const first_evidence =
        inventory.evidenceAt(0) orelse
        return error.TestUnexpectedResult;

    const second_evidence =
        inventory.evidenceAt(1) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(
        !first_evidence.observation.eqlExact(
            second_evidence.observation,
        ),
    );
}

test "identity inventory ignores non-identity observations" {
    const observation = fromJ1939(.{
        .eec1_engine_speed = .{
            .source_address = 0x00,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    });

    var inventory =
        IdentityEvidenceInventory(4, 32){};

    try std.testing.expectEqual(
        IdentityObserveResult.non_identity,
        try inventory.observe(observation),
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        inventory.count(),
    );
}

test "full identity inventory still counts repeated evidence" {
    const first = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x1003030000400064,
            },
        },
    });

    const second = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x81,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x2003030000400064,
            },
        },
    });

    var inventory =
        IdentityEvidenceInventory(1, 32){};

    _ = try inventory.observe(first);

    try std.testing.expectEqual(
        IdentityObserveResult.existing_evidence,
        try inventory.observe(first),
    );

    try std.testing.expectError(
        error.IdentityEvidenceCapacityExceeded,
        inventory.observe(second),
    );

    const evidence =
        inventory.evidenceAt(0) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(usize, 2),
        evidence.occurrence_count,
    );
}

test "identity inventory keeps same evidence separate across endpoints" {
    const first = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x1003030000400064,
            },
        },
    });

    const second = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x81,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x1003030000400064,
            },
        },
    });

    var inventory =
        IdentityEvidenceInventory(4, 32){};

    try std.testing.expectEqual(
        IdentityObserveResult.new_evidence,
        try inventory.observe(first),
    );

    try std.testing.expectEqual(
        IdentityObserveResult.new_evidence,
        try inventory.observe(second),
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        inventory.count(),
    );
}

test "identity inventory queries distinct evidence by endpoint" {
    const first = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x1003030000400064,
            },
        },
    });

    const conflicting = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x2003030000400064,
            },
        },
    });

    const other_endpoint = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x81,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x1003030000400064,
            },
        },
    });

    var inventory =
        IdentityEvidenceInventory(4, 32){};

    _ = try inventory.observe(first);
    _ = try inventory.observe(first);
    _ = try inventory.observe(conflicting);
    _ = try inventory.observe(other_endpoint);

    try std.testing.expectEqual(
        @as(usize, 2),
        inventory.evidenceCountForEndpoint(.{
            .j1939_source_address = 0x80,
        }),
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        inventory.evidenceCountForEndpoint(.{
            .j1939_source_address = 0x81,
        }),
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        inventory.evidenceCountForEndpoint(.{
            .j1939_source_address = 0x82,
        }),
    );

    const first_evidence =
        inventory.evidenceForEndpointAt(
            .{
                .j1939_source_address = 0x80,
            },
            0,
        ) orelse
        return error.TestUnexpectedResult;

    const second_evidence =
        inventory.evidenceForEndpointAt(
            .{
                .j1939_source_address = 0x80,
            },
            1,
        ) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(usize, 2),
        first_evidence.occurrence_count,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        second_evidence.occurrence_count,
    );

    try std.testing.expect(
        first_evidence.observation.endpoint.eql(.{
            .j1939_source_address = 0x80,
        }),
    );

    try std.testing.expect(
        second_evidence.observation.endpoint.eql(.{
            .j1939_source_address = 0x80,
        }),
    );

    try std.testing.expect(
        inventory.evidenceForEndpointAt(
            .{
                .j1939_source_address = 0x80,
            },
            2,
        ) == null,
    );
}
