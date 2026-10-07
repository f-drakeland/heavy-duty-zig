const std = @import("std");

const j1708 = @import("j1708.zig");
const structure = @import("j1587/structure.zig");

pub const RecoveryStatus = enum {
    recovered,
    ambiguous,
    unrecoverable,
};

pub const ScratchState = enum(u8) {
    none,
    one,
    multiple,
};

pub const RecoveryError = error{
    ScratchTooSmall,
};

pub const RecoveryResult = union(enum) {
    recovered: RecoveredFrames,
    ambiguous,
    unrecoverable,
};

pub const RecoveredFrames = struct {
    chunk: []const u8,
    scratch: []const ScratchState,
    start: usize = 0,

    pub fn next(self: *RecoveredFrames) ?j1708.FrameView {
        if (self.start == self.chunk.len) return null;

        var end = self.start + 2;
        while (end <= self.chunk.len) : (end += 1) {
            if (self.scratch[end] != .one) continue;
            if (!isCandidate(self.chunk[self.start..end])) continue;

            const frame = j1708.FrameView.fromDelimited(
                self.chunk[self.start..end],
            ) catch unreachable;

            self.start = end;
            return frame;
        }

        // A RecoveredFrames value is only constructed after classify()
        // proves that exactly one complete interpretation exists.
        unreachable;
    }
};

pub fn requiredScratchLen(chunk_len: usize) usize {
    return chunk_len + 1;
}

pub fn classify(
    chunk: []const u8,
    scratch: []ScratchState,
) RecoveryError!RecoveryStatus {
    if (chunk.len == 0) return .unrecoverable;

    if (scratch.len < requiredScratchLen(chunk.len)) {
        return error.ScratchTooSmall;
    }

    // The empty suffix has exactly one way to finish:
    // there is nothing left to explain.
    scratch[chunk.len] = .one;

    var start = chunk.len;
    while (start > 0) {
        start -= 1;

        var total: ScratchState = .none;

        var end = start + 2;
        while (end <= chunk.len) : (end += 1) {
            if (!isCandidate(chunk[start..end])) continue;

            total = combine(total, scratch[end]);

            // We only care about 0, 1, or 2+ interpretations.
            if (total == .multiple) break;
        }

        scratch[start] = total;
    }

    return switch (scratch[0]) {
        .none => .unrecoverable,
        .one => .recovered,
        .multiple => .ambiguous,
    };
}

pub fn recover(
    chunk: []const u8,
    scratch: []ScratchState,
) RecoveryError!RecoveryResult {
    const status = try classify(chunk, scratch);

    return switch (status) {
        .recovered => .{
            .recovered = .{
                .chunk = chunk,
                .scratch = scratch[0..requiredScratchLen(chunk.len)],
            },
        },
        .ambiguous => .ambiguous,
        .unrecoverable => .unrecoverable,
    };
}

fn isCandidate(raw: []const u8) bool {
    const frame = j1708.FrameView.fromDelimited(raw) catch return false;

    return switch (structure.inspectFrame(frame)) {
        .invalid => false,

        // Unknown structure is deliberately preserved rather than
        // treated as evidence that the boundary is impossible.
        .not_j1587,
        .valid,
        .unknown,
        => true,
    };
}

fn combine(
    existing: ScratchState,
    additional: ScratchState,
) ScratchState {
    return switch (additional) {
        .none => existing,
        .multiple => .multiple,
        .one => switch (existing) {
            .none => .one,
            .one, .multiple => .multiple,
        },
    };
}

test "one complete interpretation is recovered" {
    const chunk = [_]u8{
        128, 84, 0, 44,
    };

    var scratch: [chunk.len + 1]ScratchState = undefined;

    try std.testing.expectEqual(
        RecoveryStatus.recovered,
        try classify(&chunk, &scratch),
    );
}

test "unique multi-frame interpretation is recovered" {
    const chunk = [_]u8{
        128, 0, 0, 128,
        128, 0, 0, 128,
    };

    var scratch: [chunk.len + 1]ScratchState = undefined;

    try std.testing.expectEqual(
        RecoveryStatus.recovered,
        try classify(&chunk, &scratch),
    );
}

test "multiple complete interpretations are ambiguous" {
    const chunk = [_]u8{
        128, 84,  0, 44,
        128, 194, 0, 190,
    };

    var scratch: [chunk.len + 1]ScratchState = undefined;

    try std.testing.expectEqual(
        RecoveryStatus.ambiguous,
        try classify(&chunk, &scratch),
    );
}

test "no complete interpretation is unrecoverable" {
    const chunk = [_]u8{
        128, 84, 0, 45,
    };

    var scratch: [chunk.len + 1]ScratchState = undefined;

    try std.testing.expectEqual(
        RecoveryStatus.unrecoverable,
        try classify(&chunk, &scratch),
    );
}

test "classification reports insufficient scratch space" {
    const chunk = [_]u8{
        128, 84, 0, 44,
    };

    var scratch: [4]ScratchState = undefined;

    try std.testing.expectError(
        error.ScratchTooSmall,
        classify(&chunk, &scratch),
    );
}

test "recovered result walks the unique frame interpretation" {
    const chunk = [_]u8{
        128, 0, 0, 128,
        128, 0, 0, 128,
    };

    var scratch: [chunk.len + 1]ScratchState = undefined;

    var result = try recover(&chunk, &scratch);

    switch (result) {
        .recovered => |*frames| {
            const first = frames.next().?;
            const second = frames.next().?;

            try std.testing.expectEqualSlices(
                u8,
                chunk[0..4],
                first.bytes(),
            );

            try std.testing.expectEqualSlices(
                u8,
                chunk[4..8],
                second.bytes(),
            );

            try std.testing.expect(frames.next() == null);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "recover does not choose among ambiguous interpretations" {
    const chunk = [_]u8{
        128, 84,  0, 44,
        128, 194, 0, 190,
    };

    var scratch: [chunk.len + 1]ScratchState = undefined;

    const result = try recover(&chunk, &scratch);

    try std.testing.expect(result == .ambiguous);
}
