const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Module
    const web3_module = b.addModule("web", .{
        .source_file = .{
            .path = "src/web3.zig",
        },
        .dependencies = &.{},
    });
    try b.modules.put(b.dupe("web3"), web3_module);

    // Creates a step for unit testing
    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/web3.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // Run tests step
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Examples
    const example_dir_path = try std.fs.path.join(b.allocator, &[_][]const u8{ "src", "examples" });
    const examples_dir = std.fs.cwd().openIterableDir(example_dir_path, .{}) catch return;

    var examples_dir_iter = examples_dir.iterate();
    while (try examples_dir_iter.next()) |path| {
        switch (path.kind) {
            .file => {
                if (std.mem.eql(u8, std.fs.path.extension(path.name), ".zig")) {
                    const example_path = std.fs.path.join(b.allocator, &[_][]const u8{ example_dir_path, path.name }) catch @panic("Out of memory");
                    const exe = b.addExecutable(.{
                        .name = std.fs.path.stem(path.name),
                        .root_source_file = .{ .path = example_path },
                        .target = target,
                        .optimize = optimize,
                    });

                    exe.addModule("web3", web3_module);

                    b.installArtifact(exe);

                    const run_cmd = b.addRunArtifact(exe);
                    run_cmd.step.dependOn(b.getInstallStep());

                    // Pass args
                    if (b.args) |args| {
                        run_cmd.addArgs(args);
                    }

                    const step_name = std.mem.join(b.allocator, "_", &[_][]const u8{ "example", std.fs.path.stem(path.name) }) catch @panic("Out of memory");
                    const step_desc = std.mem.join(b.allocator, "", &[_][]const u8{ "Run example \"", example_path, "\"" }) catch @panic("Out of memory");

                    const run_step = b.step(step_name, step_desc);
                    run_step.dependOn(&run_cmd.step);
                }
            },
            else => continue,
        }
    }
}
