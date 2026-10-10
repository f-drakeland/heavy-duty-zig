const std = @import("std");

const j1587 = @import("j1587.zig");
const j1939 = @import("j1939.zig");

const isotp = @import("isotp.zig");
const uds = @import("uds.zig");

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
/// Durable diagnostic evidence reported by one protocol endpoint.
///
/// These variants preserve the protocol-specific diagnostic representation.
/// They do not unify J1587 and J1939 fault semantics or establish permanent
/// controller or physical ECU identity.
///
/// The currently supported variants contain only value data and therefore do
/// not retain borrowed parser or reassembly storage.
pub const OwnedDiagnosticEvidence = union(enum) {
    const Self = @This();

    j1587_diagnostic_code: j1587.DiagnosticCode,
    j1939_dm1_lamps: j1939.Dm1LampObservation,
    j1939_dm1_diagnostic_trouble_code: j1939.Dm1DiagnosticTroubleCodeObservation,

    pub fn fromEndpointObservation(
        observation: EndpointObservation,
    ) ?Self {
        return switch (observation.evidence) {
            .j1587 => |evidence| switch (evidence) {
                .diagnostic_code => |value| .{
                    .j1587_diagnostic_code = value,
                },

                else => null,
            },

            .j1939 => |evidence| switch (evidence) {
                .dm1_lamps => |value| .{
                    .j1939_dm1_lamps = value,
                },

                .dm1_diagnostic_trouble_code => |value| .{
                    .j1939_dm1_diagnostic_trouble_code = value,
                },

                else => null,
            },
        };
    }

    pub fn endpoint(
        self: *const Self,
    ) EndpointKey {
        return switch (self.*) {
            .j1587_diagnostic_code => |value| .{
                .j1587_mid = value.source_mid,
            },

            .j1939_dm1_lamps => |value| .{
                .j1939_source_address = value.source_address,
            },

            .j1939_dm1_diagnostic_trouble_code => |value| .{
                .j1939_source_address = value.source_address,
            },
        };
    }

    pub fn eqlExact(
        self: *const Self,
        other: *const Self,
    ) bool {
        return switch (self.*) {
            .j1587_diagnostic_code => |value| switch (other.*) {
                .j1587_diagnostic_code => |other_value| std.meta.eql(value, other_value),

                else => false,
            },

            .j1939_dm1_lamps => |value| switch (other.*) {
                .j1939_dm1_lamps => |other_value| std.meta.eql(value, other_value),

                else => false,
            },

            .j1939_dm1_diagnostic_trouble_code => |value| switch (other.*) {
                .j1939_dm1_diagnostic_trouble_code => |other_value| std.meta.eql(value, other_value),

                else => false,
            },
        };
    }
};

/// Borrowed UDS data-identifier evidence with the ISO-TP route on which it
/// was observed.
///
/// The source/destination bytes are capture-local routing evidence. This does
/// not establish controller, component, vehicle, or physical-device identity.
pub const UdsDataIdentifierEvidence = struct {
    source_address: u8,
    destination_address: u8,
    delivery: isotp.MessageDelivery,

    data_identifier: u16,
    data_after_identifier: []const u8,
};

pub const CorrelationStorageError = error{
    CorrelationPayloadCapacityExceeded,
};

fn OwnedBytes(comptime capacity: usize) type {
    if (capacity == 0) {
        @compileError(
            "owned correlation payload capacity must be greater than zero",
        );
    }

    return struct {
        const Self = @This();

        storage: [capacity]u8 = undefined,
        len: usize = 0,

        pub fn fromSlice(
            source: []const u8,
        ) CorrelationStorageError!Self {
            if (source.len > capacity) {
                return error.CorrelationPayloadCapacityExceeded;
            }

            var result: Self = .{};
            @memcpy(result.storage[0..source.len], source);
            result.len = source.len;

            return result;
        }

        pub fn bytes(
            self: *const Self,
        ) []const u8 {
            return self.storage[0..self.len];
        }

        pub fn eql(
            self: *const Self,
            other: *const Self,
        ) bool {
            return std.mem.eql(
                u8,
                self.bytes(),
                other.bytes(),
            );
        }
    };
}

/// Durable protocol evidence capable of participating in correlation.
///
/// This owns the exact bytes used for correlation while preserving the
/// protocol-local metadata under which those bytes were observed. It does not
/// assert controller, component, vehicle, or physical-device identity.
pub fn OwnedCorrelationEvidence(
    comptime payload_capacity: usize,
) type {
    const Payload = OwnedBytes(payload_capacity);

    return union(enum) {
        const Self = @This();

        pub const J1939ComponentIdentificationPayload = struct {
            source_address: u8,
            delivery: j1939.MessageDelivery,
            payload: Payload,
        };

        pub const UdsDataIdentifierResponse = struct {
            source_address: u8,
            destination_address: u8,
            delivery: isotp.MessageDelivery,
            data_identifier: u16,
            data_after_identifier: Payload,
        };

        j1939_component_identification_payload: J1939ComponentIdentificationPayload,
        uds_data_identifier_response: UdsDataIdentifierResponse,

        pub fn fromJ1939ComponentIdentification(
            observation: j1939.ComponentIdentificationObservation,
        ) CorrelationStorageError!?Self {
            const raw_payload =
                observation.raw_payload orelse
                return null;

            return .{
                .j1939_component_identification_payload = .{
                    .source_address = observation.source_address,
                    .delivery = observation.delivery,
                    .payload = try Payload.fromSlice(raw_payload),
                },
            };
        }

        pub fn fromUdsDataIdentifier(
            evidence: UdsDataIdentifierEvidence,
        ) CorrelationStorageError!Self {
            return .{
                .uds_data_identifier_response = .{
                    .source_address = evidence.source_address,
                    .destination_address = evidence.destination_address,
                    .delivery = evidence.delivery,
                    .data_identifier = evidence.data_identifier,
                    .data_after_identifier = try Payload.fromSlice(
                        evidence.data_after_identifier,
                    ),
                },
            };
        }

        pub fn eqlExact(
            self: *const Self,
            other: *const Self,
        ) bool {
            return switch (self.*) {
                .j1939_component_identification_payload => |value| switch (other.*) {
                    .j1939_component_identification_payload => |other_value| value.source_address == other_value.source_address and
                        value.delivery == other_value.delivery and
                        value.payload.eql(&other_value.payload),

                    else => false,
                },

                .uds_data_identifier_response => |value| switch (other.*) {
                    .uds_data_identifier_response => |other_value| value.source_address == other_value.source_address and
                        value.destination_address == other_value.destination_address and
                        value.delivery == other_value.delivery and
                        value.data_identifier == other_value.data_identifier and
                        value.data_after_identifier.eql(
                            &other_value.data_after_identifier,
                        ),

                    else => false,
                },
            };
        }
    };
}

/// Capture-local identity of one distinct durable correlation-evidence value.
///
/// This identifies evidence stored in a CorrelationEvidenceInventory. It does
/// not identify a controller, component, vehicle, or physical ECU.
pub const EvidenceValueId = struct {
    index: usize,

    pub fn eql(
        self: EvidenceValueId,
        other: EvidenceValueId,
    ) bool {
        return self.index == other.index;
    }
};

pub const EvidenceRelationshipReason = enum {
    exact_payload_equality,
};

/// Capture-local relationship between two distinct durable evidence values.
///
/// A relationship records why two values are associated. It does not merge
/// their protocol endpoints or establish controller or physical ECU identity.
pub const EvidenceRelationship = struct {
    left: EvidenceValueId,
    right: EvidenceValueId,
    reason: EvidenceRelationshipReason,
    byte_length: usize,

    pub fn eql(
        self: EvidenceRelationship,
        other: EvidenceRelationship,
    ) bool {
        if (self.reason != other.reason or
            self.byte_length != other.byte_length)
        {
            return false;
        }

        return switch (self.reason) {
            .exact_payload_equality => (self.left.eql(other.left) and
                self.right.eql(other.right)) or
                (self.left.eql(other.right) and
                    self.right.eql(other.left)),
        };
    }
};

pub const CorrelationEvidenceObserveStatus = enum {
    new_evidence,
    existing_evidence,
};

pub const CorrelationEvidenceObserveResult = struct {
    id: EvidenceValueId,
    status: CorrelationEvidenceObserveStatus,
};

pub const CorrelationInventoryError = error{
    CorrelationEvidenceCapacityExceeded,
};

/// Bounded capture-local inventory of distinct durable correlation evidence.
///
/// Exact repeated values share one EvidenceValueId and increment an occurrence
/// count. Values that differ by protocol kind or protocol metadata remain
/// distinct even when their payload bytes are equal.
pub fn CorrelationEvidenceInventory(
    comptime evidence_capacity: usize,
    comptime payload_capacity: usize,
) type {
    if (evidence_capacity == 0) {
        @compileError(
            "correlation evidence capacity must be greater than zero",
        );
    }

    const Owned = OwnedCorrelationEvidence(payload_capacity);

    return struct {
        const Self = @This();

        pub const EvidenceView = struct {
            id: EvidenceValueId,
            evidence: *const Owned,
            occurrence_count: usize,
        };

        const Slot = struct {
            occupied: bool = false,
            evidence: Owned = undefined,
            occurrence_count: usize = 0,
        };

        slots: [evidence_capacity]Slot = @splat(.{}),
        evidence_count: usize = 0,

        pub fn observe(
            self: *Self,
            owned_evidence: Owned,
        ) CorrelationInventoryError!CorrelationEvidenceObserveResult {
            for (&self.slots, 0..) |*slot, index| {
                if (slot.occupied and
                    slot.evidence.eqlExact(&owned_evidence))
                {
                    slot.occurrence_count += 1;

                    return .{
                        .id = .{ .index = index },
                        .status = .existing_evidence,
                    };
                }
            }

            for (&self.slots, 0..) |*slot, index| {
                if (!slot.occupied) {
                    slot.* = .{
                        .occupied = true,
                        .evidence = owned_evidence,
                        .occurrence_count = 1,
                    };

                    self.evidence_count += 1;

                    return .{
                        .id = .{ .index = index },
                        .status = .new_evidence,
                    };
                }
            }

            return error.CorrelationEvidenceCapacityExceeded;
        }

        /// Derives the exact cross-protocol payload relationship currently
        /// supported by HDZ.
        ///
        /// The returned orientation is canonical: J1939 evidence is `left`
        /// and UDS evidence is `right`, regardless of argument order.
        pub fn exactPayloadRelationship(
            self: *const Self,
            first_id: EvidenceValueId,
            second_id: EvidenceValueId,
        ) ?EvidenceRelationship {
            if (first_id.eql(second_id)) {
                return null;
            }

            const first =
                self.evidence(first_id) orelse
                return null;

            const second =
                self.evidence(second_id) orelse
                return null;

            return switch (first.evidence.*) {
                .j1939_component_identification_payload => |j1939_value| switch (second.evidence.*) {
                    .uds_data_identifier_response => |uds_value| {
                        if (!j1939_value.payload.eql(
                            &uds_value.data_after_identifier,
                        )) {
                            return null;
                        }

                        return .{
                            .left = first_id,
                            .right = second_id,
                            .reason = .exact_payload_equality,
                            .byte_length = j1939_value.payload.bytes().len,
                        };
                    },

                    else => null,
                },

                .uds_data_identifier_response => |uds_value| switch (second.evidence.*) {
                    .j1939_component_identification_payload => |j1939_value| {
                        if (!j1939_value.payload.eql(
                            &uds_value.data_after_identifier,
                        )) {
                            return null;
                        }

                        return .{
                            .left = second_id,
                            .right = first_id,
                            .reason = .exact_payload_equality,
                            .byte_length = j1939_value.payload.bytes().len,
                        };
                    },

                    else => null,
                },
            };
        }

        pub fn count(
            self: *const Self,
        ) usize {
            return self.evidence_count;
        }

        pub fn evidence(
            self: *const Self,
            id: EvidenceValueId,
        ) ?EvidenceView {
            if (id.index >= evidence_capacity) {
                return null;
            }

            const slot = &self.slots[id.index];

            if (!slot.occupied) {
                return null;
            }

            return .{
                .id = id,
                .evidence = &slot.evidence,
                .occurrence_count = slot.occurrence_count,
            };
        }
    };
}

/// Capture-local identity of one durable evidence relationship.
pub const EvidenceRelationshipId = struct {
    index: usize,

    pub fn eql(
        self: EvidenceRelationshipId,
        other: EvidenceRelationshipId,
    ) bool {
        return self.index == other.index;
    }
};

pub const EvidenceRelationshipRecordStatus = enum {
    new_relationship,
    existing_relationship,
};

pub const EvidenceRelationshipRecordResult = struct {
    id: EvidenceRelationshipId,
    status: EvidenceRelationshipRecordStatus,
};

pub const EvidenceRelationshipInventoryError = error{
    EvidenceRelationshipCapacityExceeded,
    InvalidEvidenceRelationship,
};

/// Bounded capture-local inventory of relationships between durable evidence
/// values.
///
/// EvidenceValueIds supplied here must belong to the same capture-local
/// CorrelationEvidenceInventory. Relationships preserve associations between
/// evidence values; they do not merge those values or their protocol endpoints.
pub fn EvidenceRelationshipInventory(
    comptime capacity: usize,
) type {
    if (capacity == 0) {
        @compileError(
            "evidence relationship capacity must be greater than zero",
        );
    }

    return struct {
        const Self = @This();

        pub const RelationshipView = struct {
            id: EvidenceRelationshipId,
            relationship: *const EvidenceRelationship,
        };

        const Slot = struct {
            occupied: bool = false,
            relationship: EvidenceRelationship = undefined,
        };

        slots: [capacity]Slot = @splat(.{}),
        relationship_count: usize = 0,

        pub fn record(
            self: *Self,
            candidate: EvidenceRelationship,
        ) EvidenceRelationshipInventoryError!EvidenceRelationshipRecordResult {
            if (candidate.left.eql(candidate.right)) {
                return error.InvalidEvidenceRelationship;
            }

            for (&self.slots, 0..) |*slot, index| {
                if (slot.occupied and
                    slot.relationship.eql(candidate))
                {
                    return .{
                        .id = .{ .index = index },
                        .status = .existing_relationship,
                    };
                }
            }

            for (&self.slots, 0..) |*slot, index| {
                if (!slot.occupied) {
                    slot.* = .{
                        .occupied = true,
                        .relationship = candidate,
                    };

                    self.relationship_count += 1;

                    return .{
                        .id = .{ .index = index },
                        .status = .new_relationship,
                    };
                }
            }

            return error.EvidenceRelationshipCapacityExceeded;
        }

        pub fn count(
            self: *const Self,
        ) usize {
            return self.relationship_count;
        }

        pub fn relationship(
            self: *const Self,
            id: EvidenceRelationshipId,
        ) ?RelationshipView {
            if (id.index >= capacity) {
                return null;
            }

            const slot = &self.slots[id.index];

            if (!slot.occupied) {
                return null;
            }

            return .{
                .id = id,
                .relationship = &slot.relationship,
            };
        }

        pub fn relationshipCountForEvidence(
            self: *const Self,
            evidence_id: EvidenceValueId,
        ) usize {
            var result: usize = 0;

            for (&self.slots) |*slot| {
                if (!slot.occupied) {
                    continue;
                }

                if (slot.relationship.left.eql(evidence_id) or
                    slot.relationship.right.eql(evidence_id))
                {
                    result += 1;
                }
            }

            return result;
        }

        pub fn relationshipForEvidenceAt(
            self: *const Self,
            evidence_id: EvidenceValueId,
            index: usize,
        ) ?RelationshipView {
            var matching_index: usize = 0;

            for (&self.slots, 0..) |*slot, slot_index| {
                if (!slot.occupied) {
                    continue;
                }

                if (!slot.relationship.left.eql(evidence_id) and
                    !slot.relationship.right.eql(evidence_id))
                {
                    continue;
                }

                if (matching_index == index) {
                    return .{
                        .id = .{ .index = slot_index },
                        .relationship = &slot.relationship,
                    };
                }

                matching_index += 1;
            }

            return null;
        }
    };
}

/// Exact equality between an original J1939 Component Identification payload
/// and the bytes following a UDS data identifier.
///
/// This records a byte-for-byte relationship only. It does not assert that
/// the DID means J1939 Component Identification or that the two protocol
/// addresses identify the same physical controller.
pub const J1939UdsExactPayloadMatch = struct {
    j1939_source_address: u8,
    j1939_delivery: j1939.MessageDelivery,

    uds_source_address: u8,
    uds_destination_address: u8,
    uds_delivery: isotp.MessageDelivery,

    data_identifier: u16,
    byte_length: usize,
};

pub fn matchJ1939ComponentPayloadToUdsDataIdentifier(
    component: j1939.ComponentIdentificationObservation,
    uds_evidence: UdsDataIdentifierEvidence,
) ?J1939UdsExactPayloadMatch {
    const raw_payload =
        component.raw_payload orelse
        return null;

    if (!std.mem.eql(
        u8,
        raw_payload,
        uds_evidence.data_after_identifier,
    )) {
        return null;
    }

    return .{
        .j1939_source_address = component.source_address,
        .j1939_delivery = component.delivery,

        .uds_source_address = uds_evidence.source_address,
        .uds_destination_address = uds_evidence.destination_address,
        .uds_delivery = uds_evidence.delivery,

        .data_identifier = uds_evidence.data_identifier,
        .byte_length = raw_payload.len,
    };
}

pub const UdsDataIdentifierEvidenceError =
    uds.ParseError ||
    uds.ReadDataByIdentifierParseError;

pub fn fromUdsReadDataByIdentifierResponse(
    routed: isotp.RoutedMessage,
) UdsDataIdentifierEvidenceError!?UdsDataIdentifierEvidence {
    const message =
        try uds.parse(
            routed.payload,
        );

    const service = switch (message) {
        .service => |value| value,
        .negative_response => return null,
    };

    const response =
        (try uds.parseReadDataByIdentifierResponse(
            service,
        )) orelse
        return null;

    return .{
        .source_address = routed.source_address,
        .destination_address = routed.destination_address,
        .delivery = routed.delivery,

        .data_identifier = response.data_identifier,
        .data_after_identifier = response.data_after_identifier,
    };
}
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
    presence_count: usize,
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
/// This inventory retains capture-local endpoint presence and typed
/// observation counts independently. Each presence count represents a raw
/// sighting of that protocol endpoint supplied by the caller; it does not
/// represent a distinct device, session, or logical message.
///
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
            presence_count: usize = 0,
            observation_count: usize = 0,
        };

        slots: [capacity]Slot =
            @splat(.{}),

        endpoint_count: usize = 0,

        pub fn observePresence(
            self: *Self,
            key: EndpointKey,
        ) InventoryError!InventoryObserveResult {
            if (self.findSlot(key)) |slot| {
                slot.presence_count += 1;

                return .existing_endpoint;
            }

            const slot =
                self.findFreeSlot() orelse
                return error.EndpointCapacityExceeded;

            slot.* = .{
                .occupied = true,
                .key = key,
                .presence_count = 1,
                .observation_count = 0,
            };

            self.endpoint_count += 1;

            return .new_endpoint;
        }

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
                .presence_count = 0,
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
                        .presence_count = slot.presence_count,
                        .observation_count = slot.observation_count,
                    };
                }

                observed_index += 1;
            }

            return null;
        }

        pub fn presenceCount(
            self: *const Self,
            key: EndpointKey,
        ) ?usize {
            for (&self.slots) |*slot| {
                if (slot.occupied and
                    slot.key.eql(key))
                {
                    return slot.presence_count;
                }
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

/// Read-only capture-local view across endpoint and identity evidence.
///
/// This composes existing inventories for reporting and inspection without
/// promoting protocol endpoints to permanent controller or physical ECU
/// identities. Callers are responsible for supplying inventories populated
/// from the same capture observation stream.
pub fn CaptureCorrelationView(
    comptime endpoint_capacity: usize,
    comptime evidence_capacity: usize,
    comptime text_capacity: usize,
) type {
    const Endpoints =
        EndpointInventory(endpoint_capacity);

    const Identities =
        IdentityEvidenceInventory(
            evidence_capacity,
            text_capacity,
        );

    return struct {
        const Self = @This();

        pub const EndpointView = struct {
            key: EndpointKey,
            presence_count: usize,
            observation_count: usize,
            identity_evidence_count: usize,
        };

        endpoints: *const Endpoints,
        identities: *const Identities,

        pub fn init(
            endpoints: *const Endpoints,
            identities: *const Identities,
        ) Self {
            return .{
                .endpoints = endpoints,
                .identities = identities,
            };
        }

        pub fn count(
            self: *const Self,
        ) usize {
            return self.endpoints.count();
        }

        pub fn endpointAt(
            self: *const Self,
            index: usize,
        ) ?EndpointView {
            const endpoint =
                self.endpoints.endpointAt(index) orelse
                return null;

            return .{
                .key = endpoint.key,
                .presence_count = endpoint.presence_count,
                .observation_count = endpoint.observation_count,
                .identity_evidence_count = self.identities
                    .evidenceCountForEndpoint(
                    endpoint.key,
                ),
            };
        }

        pub fn identityEvidenceAt(
            self: *const Self,
            key: EndpointKey,
            index: usize,
        ) ?Identities.EvidenceView {
            return self.identities
                .evidenceForEndpointAt(
                key,
                index,
            );
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

test "owned correlation bytes preserve exact payload" {
    const Owned = OwnedBytes(4);

    const first = try Owned.fromSlice(&.{ 0x11, 0x22, 0x00, 0xff });
    const same = try Owned.fromSlice(&.{ 0x11, 0x22, 0x00, 0xff });
    const different = try Owned.fromSlice(&.{ 0x11, 0x22, 0x00, 0xfe });

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x11, 0x22, 0x00, 0xff },
        first.bytes(),
    );
    try std.testing.expect(first.eql(&same));
    try std.testing.expect(!first.eql(&different));

    try std.testing.expectError(
        error.CorrelationPayloadCapacityExceeded,
        Owned.fromSlice(&.{ 1, 2, 3, 4, 5 }),
    );
}

test "owned correlation evidence preserves protocol metadata and exact bytes" {
    const Owned = OwnedCorrelationEvidence(4);

    var j1939_payload = [_]u8{ 0x11, 0x22, 0x00, 0xff };

    const j1939_owned =
        (try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "MAKE",
            .model = "MODEL",
            .serial_number = "SERIAL",
            .unit_number = "UNIT",
            .raw_payload = j1939_payload[0..],
        })).?;

    j1939_payload[0] = 0xaa;

    switch (j1939_owned) {
        .j1939_component_identification_payload => |value| {
            try std.testing.expectEqual(
                @as(u8, 0x00),
                value.source_address,
            );
            try std.testing.expectEqual(
                j1939.MessageDelivery.rts_cts,
                value.delivery,
            );
            try std.testing.expectEqualSlices(
                u8,
                &.{ 0x11, 0x22, 0x00, 0xff },
                value.payload.bytes(),
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const uds_owned = try Owned.fromUdsDataIdentifier(.{
        .source_address = 0x00,
        .destination_address = 0xf1,
        .delivery = .multi_frame,
        .data_identifier = 0xf157,
        .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xff },
    });

    switch (uds_owned) {
        .uds_data_identifier_response => |value| {
            try std.testing.expectEqual(
                @as(u8, 0x00),
                value.source_address,
            );
            try std.testing.expectEqual(
                @as(u8, 0xf1),
                value.destination_address,
            );
            try std.testing.expectEqual(
                isotp.MessageDelivery.multi_frame,
                value.delivery,
            );
            try std.testing.expectEqual(
                @as(u16, 0xf157),
                value.data_identifier,
            );
            try std.testing.expectEqualSlices(
                u8,
                &.{ 0x11, 0x22, 0x00, 0xff },
                value.data_after_identifier.bytes(),
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const missing_raw =
        try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "MAKE",
            .model = "MODEL",
            .serial_number = "SERIAL",
            .unit_number = "UNIT",
        });

    try std.testing.expect(missing_raw == null);
}

test "owned correlation evidence exact equality includes protocol metadata" {
    const Owned = OwnedCorrelationEvidence(4);

    const j1939_first =
        (try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "",
            .model = "",
            .serial_number = "",
            .unit_number = "",
            .raw_payload = &.{ 0x11, 0x22, 0x00, 0xff },
        })).?;

    const j1939_same =
        (try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "",
            .model = "",
            .serial_number = "",
            .unit_number = "",
            .raw_payload = &.{ 0x11, 0x22, 0x00, 0xff },
        })).?;

    const j1939_other_delivery =
        (try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .bam,
            .make = "",
            .model = "",
            .serial_number = "",
            .unit_number = "",
            .raw_payload = &.{ 0x11, 0x22, 0x00, 0xff },
        })).?;

    try std.testing.expect(
        j1939_first.eqlExact(&j1939_same),
    );
    try std.testing.expect(
        !j1939_first.eqlExact(&j1939_other_delivery),
    );

    const uds_first = try Owned.fromUdsDataIdentifier(.{
        .source_address = 0x00,
        .destination_address = 0xf1,
        .delivery = .multi_frame,
        .data_identifier = 0xf157,
        .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xff },
    });

    const uds_same = try Owned.fromUdsDataIdentifier(.{
        .source_address = 0x00,
        .destination_address = 0xf1,
        .delivery = .multi_frame,
        .data_identifier = 0xf157,
        .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xff },
    });

    const uds_other_did = try Owned.fromUdsDataIdentifier(.{
        .source_address = 0x00,
        .destination_address = 0xf1,
        .delivery = .multi_frame,
        .data_identifier = 0xf158,
        .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xff },
    });

    try std.testing.expect(
        uds_first.eqlExact(&uds_same),
    );
    try std.testing.expect(
        !uds_first.eqlExact(&uds_other_did),
    );
    try std.testing.expect(
        !j1939_first.eqlExact(&uds_first),
    );
}

test "correlation evidence inventory assigns stable IDs to exact values" {
    const Owned = OwnedCorrelationEvidence(4);
    const Inventory = CorrelationEvidenceInventory(4, 4);

    var inventory: Inventory = .{};

    const first = try Owned.fromUdsDataIdentifier(.{
        .source_address = 0x00,
        .destination_address = 0xf1,
        .delivery = .multi_frame,
        .data_identifier = 0xf157,
        .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xff },
    });

    const repeated = try Owned.fromUdsDataIdentifier(.{
        .source_address = 0x00,
        .destination_address = 0xf1,
        .delivery = .multi_frame,
        .data_identifier = 0xf157,
        .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xff },
    });

    const first_result = try inventory.observe(first);
    const repeated_result = try inventory.observe(repeated);

    try std.testing.expectEqual(
        CorrelationEvidenceObserveStatus.new_evidence,
        first_result.status,
    );
    try std.testing.expectEqual(
        CorrelationEvidenceObserveStatus.existing_evidence,
        repeated_result.status,
    );
    try std.testing.expect(
        first_result.id.eql(repeated_result.id),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        inventory.count(),
    );

    const view = inventory.evidence(first_result.id).?;

    try std.testing.expectEqual(
        @as(usize, 2),
        view.occurrence_count,
    );
}

test "correlation evidence inventory keeps equal payloads as distinct protocol values" {
    const Owned = OwnedCorrelationEvidence(4);
    const Inventory = CorrelationEvidenceInventory(4, 4);

    var inventory: Inventory = .{};

    const j1939_value =
        (try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "",
            .model = "",
            .serial_number = "",
            .unit_number = "",
            .raw_payload = &.{ 0x11, 0x22, 0x00, 0xff },
        })).?;

    const uds_value = try Owned.fromUdsDataIdentifier(.{
        .source_address = 0x00,
        .destination_address = 0xf1,
        .delivery = .multi_frame,
        .data_identifier = 0xf157,
        .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xff },
    });

    const j1939_result = try inventory.observe(j1939_value);
    const uds_result = try inventory.observe(uds_value);

    try std.testing.expect(
        !j1939_result.id.eql(uds_result.id),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        inventory.count(),
    );
}

test "correlation evidence inventory reports capacity exhaustion" {
    const Owned = OwnedCorrelationEvidence(1);
    const Inventory = CorrelationEvidenceInventory(1, 1);

    var inventory: Inventory = .{};

    _ = try inventory.observe(
        try Owned.fromUdsDataIdentifier(.{
            .source_address = 0x00,
            .destination_address = 0xf1,
            .delivery = .single_frame,
            .data_identifier = 0x0001,
            .data_after_identifier = &.{0x11},
        }),
    );

    try std.testing.expectError(
        error.CorrelationEvidenceCapacityExceeded,
        inventory.observe(
            try Owned.fromUdsDataIdentifier(.{
                .source_address = 0x00,
                .destination_address = 0xf1,
                .delivery = .single_frame,
                .data_identifier = 0x0002,
                .data_after_identifier = &.{0x11},
            }),
        ),
    );
}

test "correlation inventory derives exact cross-protocol payload relationship" {
    const Owned = OwnedCorrelationEvidence(4);
    const Inventory = CorrelationEvidenceInventory(4, 4);

    var inventory: Inventory = .{};

    const j1939_result = try inventory.observe(
        (try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "",
            .model = "",
            .serial_number = "",
            .unit_number = "",
            .raw_payload = &.{ 0x11, 0x22, 0x00, 0xff },
        })).?,
    );

    const uds_result = try inventory.observe(
        try Owned.fromUdsDataIdentifier(.{
            .source_address = 0x7a,
            .destination_address = 0xf1,
            .delivery = .multi_frame,
            .data_identifier = 0xf157,
            .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xff },
        }),
    );

    const relationship =
        inventory.exactPayloadRelationship(
            uds_result.id,
            j1939_result.id,
        ).?;

    try std.testing.expect(
        relationship.left.eql(j1939_result.id),
    );
    try std.testing.expect(
        relationship.right.eql(uds_result.id),
    );
    try std.testing.expectEqual(
        EvidenceRelationshipReason.exact_payload_equality,
        relationship.reason,
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        relationship.byte_length,
    );
}

test "correlation inventory rejects unsupported or unequal payload relationships" {
    const Owned = OwnedCorrelationEvidence(4);
    const Inventory = CorrelationEvidenceInventory(4, 4);

    var inventory: Inventory = .{};

    const j1939_result = try inventory.observe(
        (try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "",
            .model = "",
            .serial_number = "",
            .unit_number = "",
            .raw_payload = &.{ 0x11, 0x22, 0x00, 0xff },
        })).?,
    );

    const uds_different = try inventory.observe(
        try Owned.fromUdsDataIdentifier(.{
            .source_address = 0x00,
            .destination_address = 0xf1,
            .delivery = .multi_frame,
            .data_identifier = 0xf157,
            .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xfe },
        }),
    );

    const uds_same_bytes_other_did = try inventory.observe(
        try Owned.fromUdsDataIdentifier(.{
            .source_address = 0x00,
            .destination_address = 0xf1,
            .delivery = .multi_frame,
            .data_identifier = 0xf158,
            .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xfe },
        }),
    );

    try std.testing.expect(
        inventory.exactPayloadRelationship(
            j1939_result.id,
            uds_different.id,
        ) == null,
    );

    try std.testing.expect(
        inventory.exactPayloadRelationship(
            uds_different.id,
            uds_same_bytes_other_did.id,
        ) == null,
    );

    try std.testing.expect(
        inventory.exactPayloadRelationship(
            j1939_result.id,
            j1939_result.id,
        ) == null,
    );
}

test "relationship inventory preserves and deduplicates exact relationships" {
    const Owned = OwnedCorrelationEvidence(4);
    const EvidenceInventory = CorrelationEvidenceInventory(4, 4);
    const Relationships = EvidenceRelationshipInventory(4);

    var evidence_inventory: EvidenceInventory = .{};
    var relationships: Relationships = .{};

    const j1939_result = try evidence_inventory.observe(
        (try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "",
            .model = "",
            .serial_number = "",
            .unit_number = "",
            .raw_payload = &.{ 0x11, 0x22, 0x00, 0xff },
        })).?,
    );

    const uds_result = try evidence_inventory.observe(
        try Owned.fromUdsDataIdentifier(.{
            .source_address = 0x7a,
            .destination_address = 0xf1,
            .delivery = .multi_frame,
            .data_identifier = 0xf157,
            .data_after_identifier = &.{ 0x11, 0x22, 0x00, 0xff },
        }),
    );

    const relationship =
        evidence_inventory.exactPayloadRelationship(
            j1939_result.id,
            uds_result.id,
        ).?;

    const first = try relationships.record(relationship);

    const reversed = EvidenceRelationship{
        .left = relationship.right,
        .right = relationship.left,
        .reason = relationship.reason,
        .byte_length = relationship.byte_length,
    };

    const repeated = try relationships.record(reversed);

    try std.testing.expectEqual(
        EvidenceRelationshipRecordStatus.new_relationship,
        first.status,
    );
    try std.testing.expectEqual(
        EvidenceRelationshipRecordStatus.existing_relationship,
        repeated.status,
    );
    try std.testing.expect(first.id.eql(repeated.id));
    try std.testing.expectEqual(
        @as(usize, 1),
        relationships.count(),
    );

    const stored = relationships.relationship(first.id).?;

    try std.testing.expect(
        stored.relationship.eql(relationship),
    );
}

test "relationship inventory queries multiple associations without merging evidence" {
    const Owned = OwnedCorrelationEvidence(4);
    const EvidenceInventory = CorrelationEvidenceInventory(4, 4);
    const Relationships = EvidenceRelationshipInventory(4);

    var evidence_inventory: EvidenceInventory = .{};
    var relationships: Relationships = .{};

    const j1939_result = try evidence_inventory.observe(
        (try Owned.fromJ1939ComponentIdentification(.{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "",
            .model = "",
            .serial_number = "",
            .unit_number = "",
            .raw_payload = &.{ 1, 2, 3, 4 },
        })).?,
    );

    const uds_first = try evidence_inventory.observe(
        try Owned.fromUdsDataIdentifier(.{
            .source_address = 0x7a,
            .destination_address = 0xf1,
            .delivery = .multi_frame,
            .data_identifier = 0xf157,
            .data_after_identifier = &.{ 1, 2, 3, 4 },
        }),
    );

    const uds_second = try evidence_inventory.observe(
        try Owned.fromUdsDataIdentifier(.{
            .source_address = 0x7a,
            .destination_address = 0xf1,
            .delivery = .multi_frame,
            .data_identifier = 0xf158,
            .data_after_identifier = &.{ 1, 2, 3, 4 },
        }),
    );

    _ = try relationships.record(
        evidence_inventory.exactPayloadRelationship(
            j1939_result.id,
            uds_first.id,
        ).?,
    );

    _ = try relationships.record(
        evidence_inventory.exactPayloadRelationship(
            j1939_result.id,
            uds_second.id,
        ).?,
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        relationships.relationshipCountForEvidence(
            j1939_result.id,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        relationships.relationshipCountForEvidence(
            uds_first.id,
        ),
    );
    try std.testing.expect(
        relationships.relationshipForEvidenceAt(
            j1939_result.id,
            0,
        ) != null,
    );
    try std.testing.expect(
        relationships.relationshipForEvidenceAt(
            j1939_result.id,
            1,
        ) != null,
    );
    try std.testing.expect(
        relationships.relationshipForEvidenceAt(
            j1939_result.id,
            2,
        ) == null,
    );
}

test "owned diagnostic evidence preserves protocol-specific fault evidence" {
    const j1587_evidence =
        OwnedDiagnosticEvidence.fromEndpointObservation(
            fromJ1587(.{
                .diagnostic_code = .{
                    .source_mid = 128,
                    .identifier_kind = .pid,
                    .identifier = 194,
                    .fmi = 5,
                    .status = .active,
                    .occurrence_count = 7,
                },
            }),
        ).?;

    try std.testing.expect(
        j1587_evidence.endpoint().eql(.{
            .j1587_mid = 128,
        }),
    );

    switch (j1587_evidence) {
        .j1587_diagnostic_code => |value| {
            try std.testing.expectEqual(
                @as(u16, 194),
                value.identifier,
            );
            try std.testing.expectEqual(
                @as(?u8, 7),
                value.occurrence_count,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const j1939_evidence =
        OwnedDiagnosticEvidence.fromEndpointObservation(
            fromJ1939(.{
                .dm1_diagnostic_trouble_code = .{
                    .source_address = 0x00,
                    .delivery = .bam,
                    .trouble_code = .{
                        .spn = 1234,
                        .fmi = 3,
                        .occurrence_count = 9,
                        .conversion_method = false,
                        .raw = .{ 0x11, 0x22, 0x33, 0x44 },
                    },
                },
            }),
        ).?;

    try std.testing.expect(
        j1939_evidence.endpoint().eql(.{
            .j1939_source_address = 0x00,
        }),
    );

    switch (j1939_evidence) {
        .j1939_dm1_diagnostic_trouble_code => |value| {
            try std.testing.expectEqual(
                @as(?u32, 1234),
                value.trouble_code.spn,
            );
            try std.testing.expectEqual(
                @as(u8, 9),
                value.trouble_code.occurrence_count,
            );
        },

        else => return error.TestUnexpectedResult,
    }
}

test "owned diagnostic evidence uses exact protocol evidence equality" {
    const first =
        OwnedDiagnosticEvidence.fromEndpointObservation(
            fromJ1587(.{
                .diagnostic_code = .{
                    .source_mid = 128,
                    .identifier_kind = .pid,
                    .identifier = 194,
                    .fmi = 5,
                    .status = .active,
                    .occurrence_count = 7,
                },
            }),
        ).?;

    const repeated =
        OwnedDiagnosticEvidence.fromEndpointObservation(
            fromJ1587(.{
                .diagnostic_code = .{
                    .source_mid = 128,
                    .identifier_kind = .pid,
                    .identifier = 194,
                    .fmi = 5,
                    .status = .active,
                    .occurrence_count = 7,
                },
            }),
        ).?;

    const changed_reported_count =
        OwnedDiagnosticEvidence.fromEndpointObservation(
            fromJ1587(.{
                .diagnostic_code = .{
                    .source_mid = 128,
                    .identifier_kind = .pid,
                    .identifier = 194,
                    .fmi = 5,
                    .status = .active,
                    .occurrence_count = 8,
                },
            }),
        ).?;

    try std.testing.expect(
        first.eqlExact(&repeated),
    );

    try std.testing.expect(
        !first.eqlExact(&changed_reported_count),
    );

    try std.testing.expect(
        OwnedDiagnosticEvidence.fromEndpointObservation(
            fromJ1939(.{
                .eec1_engine_speed = .{
                    .source_address = 0x00,
                    .delivery = .single_frame,
                    .raw = 0x25c0,
                    .rpm = 1208.0,
                },
            }),
        ) == null,
    );
}

test "owned diagnostic evidence preserves J1939 DM1 lamp state" {
    const first =
        OwnedDiagnosticEvidence.fromEndpointObservation(
            fromJ1939(.{
                .dm1_lamps = .{
                    .source_address = 0x80,
                    .delivery = .single_frame,
                    .statuses = .{
                        .malfunction_indicator = .on,
                        .red_stop = .off,
                        .amber_warning = .on,
                        .protect = .off,
                    },
                    .flashes = .{
                        .malfunction_indicator = .slow,
                        .red_stop = .slow,
                        .amber_warning = .fast,
                        .protect = .slow,
                    },
                },
            }),
        ).?;

    const repeated =
        OwnedDiagnosticEvidence.fromEndpointObservation(
            fromJ1939(.{
                .dm1_lamps = .{
                    .source_address = 0x80,
                    .delivery = .single_frame,
                    .statuses = .{
                        .malfunction_indicator = .on,
                        .red_stop = .off,
                        .amber_warning = .on,
                        .protect = .off,
                    },
                    .flashes = .{
                        .malfunction_indicator = .slow,
                        .red_stop = .slow,
                        .amber_warning = .fast,
                        .protect = .slow,
                    },
                },
            }),
        ).?;

    try std.testing.expect(
        first.endpoint().eql(.{
            .j1939_source_address = 0x80,
        }),
    );

    try std.testing.expect(
        first.eqlExact(&repeated),
    );

    switch (first) {
        .j1939_dm1_lamps => |value| {
            try std.testing.expectEqual(
                j1939.dm1.LampStatus.on,
                value.statuses.malfunction_indicator,
            );
            try std.testing.expectEqual(
                j1939.dm1.LampFlash.fast,
                value.flashes.amber_warning,
            );
        },

        else => return error.TestUnexpectedResult,
    }
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

test "inventory tracks raw presence separately from typed observations" {
    const key: EndpointKey = .{
        .j1939_source_address = 0x02,
    };

    const observation = fromJ1939(.{
        .eec1_engine_speed = .{
            .source_address = 0x02,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    });

    var inventory = EndpointInventory(4){};

    try std.testing.expectEqual(
        InventoryObserveResult.new_endpoint,
        try inventory.observePresence(key),
    );

    try std.testing.expectEqual(
        InventoryObserveResult.existing_endpoint,
        try inventory.observePresence(key),
    );

    try std.testing.expectEqual(
        @as(?usize, 2),
        inventory.presenceCount(key),
    );

    try std.testing.expectEqual(
        @as(?usize, 0),
        inventory.observationCount(key),
    );

    try std.testing.expectEqual(
        InventoryObserveResult.existing_endpoint,
        try inventory.observe(observation),
    );

    try std.testing.expectEqual(
        @as(?usize, 2),
        inventory.presenceCount(key),
    );

    try std.testing.expectEqual(
        @as(?usize, 1),
        inventory.observationCount(key),
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        inventory.count(),
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

test "full inventory still counts presence for existing endpoint" {
    const key: EndpointKey = .{
        .j1939_source_address = 0x00,
    };

    var inventory = EndpointInventory(1){};

    try std.testing.expectEqual(
        InventoryObserveResult.new_endpoint,
        try inventory.observePresence(key),
    );

    try std.testing.expectEqual(
        InventoryObserveResult.existing_endpoint,
        try inventory.observePresence(key),
    );

    try std.testing.expectEqual(
        @as(?usize, 2),
        inventory.presenceCount(key),
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        inventory.count(),
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

test "capture correlation view reports endpoint identity evidence" {
    const claim_a = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x1003030000400064,
            },
        },
    });

    const claim_b = fromJ1939(.{
        .address_claim = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .name = .{
                .raw = 0x2003030000400064,
            },
        },
    });

    const engine_speed = fromJ1939(.{
        .eec1_engine_speed = .{
            .source_address = 0x80,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    });

    const other_endpoint = fromJ1939(.{
        .eec1_engine_speed = .{
            .source_address = 0x81,
            .delivery = .single_frame,
            .raw = 0x25c0,
            .rpm = 1208.0,
        },
    });

    var endpoints =
        EndpointInventory(4){};

    var identities =
        IdentityEvidenceInventory(4, 32){};

    const observations = [_]EndpointObservation{
        claim_a,
        claim_a,
        claim_b,
        engine_speed,
        other_endpoint,
    };

    for (observations) |observation| {
        _ = try endpoints.observe(
            observation,
        );

        _ = try identities.observe(
            observation,
        );
    }

    const View =
        CaptureCorrelationView(
            4,
            4,
            32,
        );

    const view =
        View.init(
            &endpoints,
            &identities,
        );

    try std.testing.expectEqual(
        @as(usize, 2),
        view.count(),
    );

    const first_endpoint =
        view.endpointAt(0) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(
        first_endpoint.key.eql(.{
            .j1939_source_address = 0x80,
        }),
    );

    try std.testing.expectEqual(
        @as(usize, 4),
        first_endpoint.observation_count,
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        first_endpoint.identity_evidence_count,
    );

    const first_identity =
        view.identityEvidenceAt(
            first_endpoint.key,
            0,
        ) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(usize, 2),
        first_identity.occurrence_count,
    );

    const second_endpoint =
        view.endpointAt(1) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(usize, 1),
        second_endpoint.observation_count,
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        second_endpoint.identity_evidence_count,
    );
}

test "authentic J1939 capture fragment builds participant correlation" {
    const candump = @import("candump.zig");

    const text =
        \\(001.000000) can1 18EEFFF9 [8] 00 00 01 00 00 00 00 00
        \\(001.010000) can1 18EA00F9 [3] EB FE 00
        \\(001.020000) can1 1CECF900 [8] 10 21 00 05 FF EB FE 00
        \\(001.030000) can1 1CEC00F9 [8] 11 05 01 FF FF EB FE 00
        \\(001.040000) can1 1CEBF900 [8] 01 44 54 44 53 43 2A 34
        \\(001.050000) can1 1CEBF900 [8] 02 37 31 4E 31 30 2A 53
        \\(001.060000) can1 1CEBF900 [8] 03 30 30 36 36 39 35 31
        \\(001.070000) can1 1CEBF900 [8] 04 2A 36 31 31 30 33 35
        \\(001.080000) can1 1CEBF900 [8] 05 00 00 00 00 2A FF FF
        \\(001.090000) can1 1CECF900 [8] FF FF FF FF FF EB FE 00
    ;

    var assembler =
        j1939.MessageAssembler(
            64,
            4,
        ){};

    var endpoints =
        EndpointInventory(8){};

    var identities =
        IdentityEvidenceInventory(
            8,
            64,
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

        const record =
            try candump.parseLine(
                trimmed,
            );

        const can_frame =
            try record.frame();

        const frame =
            try j1939.FrameView.fromCanFrame(
                can_frame,
            );

        const maybe_assembly_event =
            try assembler.pushFrame(
                frame,
            );

        const assembly_event =
            maybe_assembly_event orelse
            continue;

        switch (assembly_event) {
            .message => |message| {
                var cursor =
                    try j1939.MessageCursor.init(
                        message,
                    );

                while (try cursor.next()) |event| {
                    switch (event) {
                        .observation => |observation| {
                            const endpoint_observation =
                                fromJ1939(
                                    observation,
                                );

                            _ = try endpoints.observe(
                                endpoint_observation,
                            );

                            _ = try identities.observe(
                                endpoint_observation,
                            );
                        },

                        .unsupported_pgn => {},
                    }
                }
            },

            else => {},
        }
    }

    const View =
        CaptureCorrelationView(
            8,
            8,
            64,
        );

    const view =
        View.init(
            &endpoints,
            &identities,
        );

    try std.testing.expectEqual(
        @as(usize, 2),
        view.count(),
    );

    try std.testing.expectEqual(
        @as(?usize, 1),
        endpoints.observationCount(.{
            .j1939_source_address = 0xf9,
        }),
    );

    try std.testing.expectEqual(
        @as(?usize, 1),
        endpoints.observationCount(.{
            .j1939_source_address = 0x00,
        }),
    );

    const requester_identity =
        view.identityEvidenceAt(
            .{
                .j1939_source_address = 0xf9,
            },
            0,
        ) orelse
        return error.TestUnexpectedResult;

    switch (requester_identity.observation.evidence) {
        .j1939_address_claim => |claim| {
            try std.testing.expectEqual(
                @as(u64, 0x0000000000010000),
                claim.name.raw,
            );
        },

        else => return error.TestUnexpectedResult,
    }

    const component_identity =
        view.identityEvidenceAt(
            .{
                .j1939_source_address = 0x00,
            },
            0,
        ) orelse
        return error.TestUnexpectedResult;

    switch (component_identity.observation.evidence) {
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

            try std.testing.expectEqualSlices(
                u8,
                "611035\x00\x00\x00\x00",
                component.fields.field(3),
            );
        },

        else => return error.TestUnexpectedResult,
    }
}
test "UDS DID evidence preserves observed route and response bytes" {
    const payload = [_]u8{
        0x62, 0xf1, 0x57,
        0x44, 0x54, 0x44,
        0x53, 0x43, 0x2a,
        0x34, 0x37, 0x31,
        0x4e, 0x31, 0x30,
        0x2a, 0x53, 0x30,
        0x30, 0x36, 0x36,
        0x39, 0x35, 0x31,
        0x2a, 0x36, 0x31,
        0x31, 0x30, 0x33,
        0x35, 0x00, 0x00,
        0x00, 0x00, 0x2a,
    };

    const routed: isotp.RoutedMessage = .{
        .source_address = 0x00,
        .destination_address = 0xf1,
        .payload = &payload,
        .delivery = .multi_frame,
    };

    const evidence =
        (try fromUdsReadDataByIdentifierResponse(
            routed,
        )) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(u8, 0x00),
        evidence.source_address,
    );

    try std.testing.expectEqual(
        @as(u8, 0xf1),
        evidence.destination_address,
    );

    try std.testing.expectEqual(
        isotp.MessageDelivery.multi_frame,
        evidence.delivery,
    );

    try std.testing.expectEqual(
        @as(u16, 0xf157),
        evidence.data_identifier,
    );

    try std.testing.expectEqualSlices(
        u8,
        payload[3..],
        evidence.data_after_identifier,
    );
}

test "matches authentic J1939 component payload to UDS DID bytes exactly" {
    const payload = [_]u8{
        0x44, 0x54, 0x44, 0x53, 0x43, 0x2a, 0x34,
        0x37, 0x31, 0x4e, 0x31, 0x30, 0x2a, 0x53,
        0x30, 0x30, 0x36, 0x36, 0x39, 0x35, 0x31,
        0x2a, 0x36, 0x31, 0x31, 0x30, 0x33, 0x35,
        0x00, 0x00, 0x00, 0x00, 0x2a,
    };

    const component: j1939.ComponentIdentificationObservation =
        .{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "DTDSC",
            .model = "471N10",
            .serial_number = "S0066951",
            .unit_number = payload[22..32],
            .raw_payload = &payload,
        };

    const uds_evidence: UdsDataIdentifierEvidence =
        .{
            .source_address = 0x00,
            .destination_address = 0xf1,
            .delivery = .multi_frame,
            .data_identifier = 0xf157,
            .data_after_identifier = &payload,
        };

    const match =
        matchJ1939ComponentPayloadToUdsDataIdentifier(
            component,
            uds_evidence,
        ) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(u8, 0x00),
        match.j1939_source_address,
    );

    try std.testing.expectEqual(
        j1939.MessageDelivery.rts_cts,
        match.j1939_delivery,
    );

    try std.testing.expectEqual(
        @as(u8, 0x00),
        match.uds_source_address,
    );

    try std.testing.expectEqual(
        @as(u8, 0xf1),
        match.uds_destination_address,
    );

    try std.testing.expectEqual(
        isotp.MessageDelivery.multi_frame,
        match.uds_delivery,
    );

    try std.testing.expectEqual(
        @as(u16, 0xf157),
        match.data_identifier,
    );

    try std.testing.expectEqual(
        payload.len,
        match.byte_length,
    );
}

test "component payload match rejects different UDS bytes" {
    const j1939_payload = [_]u8{
        'A', '*', 'B', '*', 'C', '*', 'D', '*',
    };

    const uds_payload = [_]u8{
        'A', '*', 'B', '*', 'C', '*', 'X', '*',
    };

    const component: j1939.ComponentIdentificationObservation =
        .{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "A",
            .model = "B",
            .serial_number = "C",
            .unit_number = "D",
            .raw_payload = &j1939_payload,
        };

    const uds_evidence: UdsDataIdentifierEvidence =
        .{
            .source_address = 0x00,
            .destination_address = 0xf1,
            .delivery = .single_frame,
            .data_identifier = 0x1234,
            .data_after_identifier = &uds_payload,
        };

    try std.testing.expect(
        matchJ1939ComponentPayloadToUdsDataIdentifier(
            component,
            uds_evidence,
        ) == null,
    );
}

test "component payload match requires original J1939 payload evidence" {
    const uds_payload = [_]u8{
        'A', '*', 'B', '*', 'C', '*', 'D', '*',
    };

    const component: j1939.ComponentIdentificationObservation =
        .{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "A",
            .model = "B",
            .serial_number = "C",
            .unit_number = "D",
        };

    const uds_evidence: UdsDataIdentifierEvidence =
        .{
            .source_address = 0x00,
            .destination_address = 0xf1,
            .delivery = .single_frame,
            .data_identifier = 0x1234,
            .data_after_identifier = &uds_payload,
        };

    try std.testing.expect(
        matchJ1939ComponentPayloadToUdsDataIdentifier(
            component,
            uds_evidence,
        ) == null,
    );
}

test "component payload match does not require protocol address equality" {
    const payload = [_]u8{
        'A', '*', 'B', '*', 'C', '*', 'D', '*',
    };

    const component: j1939.ComponentIdentificationObservation =
        .{
            .source_address = 0x00,
            .delivery = .rts_cts,
            .make = "A",
            .model = "B",
            .serial_number = "C",
            .unit_number = "D",
            .raw_payload = &payload,
        };

    const uds_evidence: UdsDataIdentifierEvidence =
        .{
            .source_address = 0x7a,
            .destination_address = 0xf1,
            .delivery = .single_frame,
            .data_identifier = 0x1234,
            .data_after_identifier = &payload,
        };

    const match =
        matchJ1939ComponentPayloadToUdsDataIdentifier(
            component,
            uds_evidence,
        ) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(
        @as(u8, 0x00),
        match.j1939_source_address,
    );

    try std.testing.expectEqual(
        @as(u8, 0x7a),
        match.uds_source_address,
    );
}
