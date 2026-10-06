const parser = @import("j1587/parser.zig");

pub const pid_multisection = parser.pid_multisection;
pub const pid_software_identification = parser.pid_software_identification;
pub const pid_vin = parser.pid_vin;
pub const pid_component_identification = parser.pid_component_identification;
pub const pid_total_vehicle_distance = parser.pid_total_vehicle_distance;

pub const DecodeError = parser.DecodeError;
pub const Message = parser.Message;
pub const ComponentIdentification = parser.ComponentIdentification;
pub const TotalVehicleDistance = parser.TotalVehicleDistance;

pub const parseMessage = parser.parseMessage;
pub const decodeComponentData = parser.decodeComponentData;
pub const decodeSoftwareData = parser.decodeSoftwareData;
pub const decodeVinData = parser.decodeVinData;
pub const decodeTotalVehicleDistanceData =
    parser.decodeTotalVehicleDistanceData;

pub const multisection = @import("j1587/multisection.zig");

test {
    _ = parser;
    _ = multisection;
}
