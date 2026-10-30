const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("heavy_duty", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_tests = b.addRunArtifact(tests);

    const inspector_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ddec_cross_protocol_inspect.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_inspector_tests = b.addRunArtifact(inspector_tests);

    const test_step = b.step("test", "Run Heavy Duty Zig tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_inspector_tests.step);

    const demo = b.addExecutable(.{
        .name = "ddec_cross_protocol_inspect",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ddec_cross_protocol_inspect.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });

    const run_demo = b.addRunArtifact(demo);

    run_demo.addFileArg(
        b.path(
            "captures/public/cross_protocol_lineage_demo.csv",
        ),
    );

    const demo_step =
        b.step(
            "demo",
            "Run the public cross-protocol lineage demo",
        );

    demo_step.dependOn(&run_demo.step);

    const verify_demo =
        b.addRunArtifact(demo);

    verify_demo.addFileArg(
        b.path(
            "captures/public/cross_protocol_lineage_demo.csv",
        ),
    );

    verify_demo.expectStdErrEqual(
        @embedFile(
            "captures/public/cross_protocol_lineage_demo.expected.txt",
        ),
    );

    verify_demo.expectExitCode(0);

    const verify_demo_step =
        b.step(
            "verify-demo",
            "Verify the public cross-protocol lineage demo",
        );

    verify_demo_step.dependOn(&verify_demo.step);

    const fmt = b.addFmt(.{
        .paths = b.pathList(&.{
            "build.zig",
            "build.zig.zon",
            "src",
        }),
        .check = true,
    });

    const fmt_step =
        b.step(
            "fmt",
            "Check repository formatting",
        );

    fmt_step.dependOn(&fmt.step);

    const check_step =
        b.step(
            "check",
            "Run all repository verification checks",
        );

    check_step.dependOn(&fmt.step);
    check_step.dependOn(&run_tests.step);
    check_step.dependOn(&run_inspector_tests.step);
    check_step.dependOn(&verify_demo.step);
}
