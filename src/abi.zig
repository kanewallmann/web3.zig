const std = @import("std");

const web3 = @import("web3.zig");
const parser_allocator = @import("parser_allocator.zig");

// Note: This struct must be identical to `AbiInput`
const JsonAbiInput = struct {
    name: ?[]const u8,
    type: *web3.AbiType,
    indexed: ?bool,
};

// Note: This struct must be identical to `AbiOutput`
const JsonAbiOutput = struct {
    name: ?[]const u8,
    type: *web3.AbiType,
};

// Note: This struct must be identical to `AbiEntry`
const JsonAbiEntry = struct {
    name: ?[]const u8,
    type: enum { function, constructor, receive, fallback, event },
    inputs: ?[]JsonAbiInput,
    outputs: ?[]JsonAbiOutput,
    stateMutability: ?enum { pure, view, nonpayable, payable } = null,
};

/// Represents an input in an ABI entry
pub const AbiInput = struct {
    name: ?[]const u8,
    type: *web3.AbiType,
    indexed: ?bool,

    pub fn deinit(self: AbiInput, allocator: std.mem.Allocator) void {
        if (self.name) |name| {
            allocator.free(name);
        }
        self.type.deinit(allocator);
    }
};

/// Reperesents an output in an ABI entry
pub const AbiOutput = struct {
    name: ?[]const u8,
    type: *web3.AbiType,

    pub fn deinit(self: AbiOutput, allocator: std.mem.Allocator) void {
        if (self.name) |name| {
            allocator.free(name);
        }
        self.type.deinit(allocator);
    }
};

/// Represents a single ABI entry
pub const AbiEntry = struct {
    name: ?[]const u8,
    type: enum { function, constructor, receive, fallback, event },
    inputs: ?[]AbiInput,
    outputs: ?[]AbiOutput,
    state_mutability: ?enum { pure, view, nonpayable, payable },

    // Recursively frees owned memory
    pub fn deinit(self: AbiEntry, allocator: std.mem.Allocator) void {
        if (self.name) |name| {
            allocator.free(name);
        }
        if (self.inputs) |inputs| {
            for (inputs) |input| {
                input.deinit(allocator);
            }
            allocator.free(inputs);
        }
        if (self.outputs) |outputs| {
            for (outputs) |output| {
                output.deinit(allocator);
            }
            allocator.free(outputs);
        }
    }

    /// Computes the 4 byte function selector
    pub fn computeSelector(self: *const AbiEntry) ![4]u8 {
        std.debug.assert(self.type == .function);

        // Allocate temporary memory to construct the function sig
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        var allocator = gpa.allocator();
        var func_sig_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
        defer func_sig_buffer.deinit();

        var writer = func_sig_buffer.writer();
        try self.formatSignature(writer);

        var hash_buffer: [32]u8 = undefined;

        // Hash the function sig
        std.crypto.hash.sha3.Keccak256.hash(func_sig_buffer.items, &hash_buffer, .{});

        var result: [4]u8 = undefined;
        @memcpy(&result, hash_buffer[0..4]);

        return result;
    }

    /// Computes the log topic for this event
    pub fn computeTopic(self: *const AbiEntry) !web3.Hash {
        std.debug.assert(self.type == .event);

        // Allocate temporary memory to construct the function sig
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        var allocator = gpa.allocator();
        var func_sig_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
        defer func_sig_buffer.deinit();

        var writer = func_sig_buffer.writer();
        try self.formatSignature(writer);

        var hash_buffer: [32]u8 = undefined;

        // Hash the function sig
        std.crypto.hash.sha3.Keccak256.hash(func_sig_buffer.items, &hash_buffer, .{});

        return web3.Hash.wrap(&hash_buffer);
    }

    /// Formats this entry as per the ABI function/event signature specifications
    pub fn formatSignature(self: *const AbiEntry, writer: anytype) !void {
        std.debug.assert(self.type == .event or self.type == .function);

        if (self.name == null) {
            return error.NoName;
        }
        _ = try writer.write(self.name.?);
        try writer.writeByte('(');

        if (self.inputs) |inputs| {
            var first = true;
            for (inputs) |input| {
                if (!first) {
                    try writer.writeByte(',');
                }
                first = false;
                _ = try writer.print("{}", .{input.type});
            }
        }

        try writer.writeByte(')');
    }

    /// Format helper
    pub fn format(self: *const AbiEntry, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        _ = try writer.write(@tagName(self.type));
        if (self.name) |name| {
            _ = try writer.write(" ");
            _ = try writer.write(name);
        }
        if (self.inputs) |inputs| {
            try writer.writeByte('(');
            var first = true;
            for (inputs) |input| {
                if (!first) {
                    try writer.writeByte(',');
                }
                first = false;
                _ = try writer.print("{}", .{input.type});
                if (input.indexed != null and input.indexed.?) {
                    _ = try writer.write(" indexed");
                }
                if (input.name) |name| {
                    if (name.len > 0) {
                        try writer.writeByte(' ');
                        _ = try writer.write(name);
                    }
                }
            }
            try writer.writeByte(')');
        }
        if (self.state_mutability) |state_mutability| {
            try writer.writeByte(' ');
            _ = try writer.write(@tagName(state_mutability));
        }
        if (self.outputs) |outputs| {
            _ = try writer.write(" returns (");
            var first = true;
            for (outputs) |output| {
                if (!first) {
                    try writer.writeByte(',');
                }
                first = false;
                _ = try writer.print("{}", .{output.type});
                if (output.name) |name| {
                    if (name.len > 0) {
                        try writer.writeByte(' ');
                        _ = try writer.write(name);
                    }
                }
            }
            try writer.writeByte(')');
        }
    }
};

comptime {
    // Not a perfect comparison but can catch mistakes early
    std.debug.assert(@sizeOf(JsonAbiInput) == @sizeOf(AbiInput));
    std.debug.assert(@typeInfo(JsonAbiInput).Struct.fields.len == @typeInfo(AbiInput).Struct.fields.len);
    std.debug.assert(@sizeOf(JsonAbiOutput) == @sizeOf(AbiOutput));
    std.debug.assert(@typeInfo(JsonAbiOutput).Struct.fields.len == @typeInfo(AbiOutput).Struct.fields.len);
    std.debug.assert(@sizeOf(JsonAbiEntry) == @sizeOf(AbiEntry));
    std.debug.assert(@typeInfo(JsonAbiEntry).Struct.fields.len == @typeInfo(AbiEntry).Struct.fields.len);
}

/// Wrapper around an array of ABI entries
pub const Abi = struct {
    const Self = @This();

    entries: []AbiEntry,

    /// Frees all owned memory
    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        for (self.entries) |entry| {
            entry.deinit(allocator);
        }
        allocator.free(self.entries);
    }

    /// Finds an ABI entry with matching method name and args
    pub fn findEntry(self: *const Self, method: []const u8, arg_types: []*const web3.AbiType) !?*web3.abi.AbiEntry {
        var entry: ?*web3.abi.AbiEntry = data: for (self.entries) |*entry| {
            if (entry.name) |entry_name| {
                if (std.mem.eql(u8, method, entry_name)) {
                    if (entry.inputs) |inputs| {
                        if (inputs.len != arg_types.len) {
                            continue;
                        }
                        for (arg_types, 0..) |arg_type, i| {
                            if (!std.meta.eql(arg_type, inputs[i].type)) {
                                continue :data;
                            }
                        }
                        break :data entry;
                    }
                }
            }
        };

        return entry;
    }

    /// Finds the first ABI entry with the given method name
    pub fn findFirstEntry(self: *const Self, method: []const u8) !?*web3.abi.AbiEntry {
        var entry: ?*web3.abi.AbiEntry = data: for (self.entries) |*entry| {
            if (entry.name) |entry_name| {
                if (std.mem.eql(u8, method, entry_name)) {
                    break :data entry;
                }
            }
        };

        return entry;
    }
};

/// Encodes appended values per ABI convention
pub const CalldataArgEncoder = struct {
    const Self = @This();

    calldata_args: std.ArrayList(u8),
    calldata_extra: std.ArrayList(u8),

    /// Initialize memory
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .calldata_args = std.ArrayList(u8).init(allocator),
            .calldata_extra = std.ArrayList(u8).init(allocator),
        };
    }

    /// Frees owned memory
    pub fn deinit(self: *Self) void {
        self.calldata_args.clearAndFree();
        self.calldata_extra.clearAndFree();
    }

    /// Appends a new value to the calldata.
    /// `arg_type` is the ABI type of the argument.
    /// `arg` is the value to coerce into the desired type.
    /// Errors if the given value cannot be coerced into the desired ABI type.
    pub fn append(self: *Self, arg_type: *const web3.AbiType, arg: anytype) !void {
        const ATT = @typeInfo(@TypeOf(arg));
        switch (ATT) {
            .Int => |arg_int| {
                switch (arg_int.signedness) {
                    .signed => {
                        switch (arg_type.*) {
                            .int => |int| {
                                const arg_i256: i256 = @intCast(arg);
                                const max_value: u256 = std.math.pow(u256, 2, int.bits - 1) - 1;
                                if (arg_i256 > max_value) {
                                    return error.IntegerOverflow;
                                }
                                const min_value: i256 = -@as(i256, @intCast(max_value)) - 1;
                                if (arg_i256 < min_value) {
                                    return error.IntegerUnderflow;
                                }
                                try self.calldata_args.ensureUnusedCapacity(32);
                                const i = self.calldata_args.items.len;
                                self.calldata_args.items.len += 32;
                                std.mem.writeIntBig(i256, self.calldata_args.items[i..][0..32], arg_i256);
                            },
                            else => return error.InvalidCoercion,
                        }
                    },
                    .unsigned => {
                        switch (arg_type.*) {
                            .uint => |uint| {
                                const arg_u256: u256 = @intCast(arg);
                                if (uint.bits < 256) {
                                    const max_value: u256 = std.math.pow(u256, 2, uint.bits) - 1;
                                    if (arg_u256 > max_value) {
                                        return error.IntegerOverflow;
                                    }
                                }
                                try self.calldata_args.ensureUnusedCapacity(32);
                                const i = self.calldata_args.items.len;
                                self.calldata_args.items.len += 32;
                                std.mem.writeIntBig(u256, self.calldata_args.items[i..][0..32], arg_u256);
                            },
                            else => return error.InvalidCoercion,
                        }
                    },
                }
            },
            .Bool => {
                switch (arg_type.*) {
                    .boolean => {
                        try self.calldata_args.ensureUnusedCapacity(32);
                        const i = self.calldata_args.items.len;
                        self.calldata_args.items.len += 32;
                        @memset(self.calldata_args.items[i..][0..32], 0);
                        if (arg) {
                            self.calldata_args.items[i + 31] = 1;
                        } else {
                            self.calldata_args.items[i + 31] = 0;
                        }
                        return;
                    },
                    else => return error.InvalidCoercion,
                }
            },
            .Struct => |struct_t| {
                _ = struct_t;
                switch (@TypeOf(arg)) {
                    web3.Address => {
                        switch (arg_type.*) {
                            .address => {
                                try self.calldata_args.ensureUnusedCapacity(32);
                                const i = self.calldata_args.items.len;
                                self.calldata_args.items.len += 32;
                                @memset(self.calldata_args.items[i..][0..32], 0);
                                @memcpy(self.calldata_args.items[i + 12 ..][0..20], arg.raw[0..20]);
                                return;
                            },
                            else => return error.InvalidCoercion,
                        }
                    },
                    else => {
                        return error.InvalidCoercion;
                    },
                }
            },
            else => unreachable,
        }
    }

    /// Returns the total size in bytes of the encoded calldata
    pub fn size(self: *const Self) usize {
        return self.calldata_args.items.len + self.calldata_extra.items.len;
    }

    /// Allocates memory for, then writes the encoded values and returns the result
    pub inline fn encodeAlloc(self: *const Self) ![]u8 {
        const total_size = self.size();
        var buffer = try self.calldata_args.allocator.alloc(u8, total_size);
        _ = try self.encodeBuf(buffer);
        return buffer;
    }

    /// Encodes the values into the supplied buffer
    pub inline fn encodeBuf(self: *const Self, buffer: []u8) !usize {
        const total_size = self.size();

        if (buffer.len < total_size) {
            return error.BufferOverflow;
        }

        @memcpy(buffer[0..self.calldata_args.items.len], self.calldata_args.items);
        @memcpy(buffer[self.calldata_args.items.len..][0..self.calldata_extra.items.len], self.calldata_extra.items);

        return total_size;
    }
};

/// Parses a JSON string into an Abi
pub fn parseJson(allocator: std.mem.Allocator, abi: []const u8) !Abi {
    var arena = parser_allocator.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    var parent_allocator = arena.allocator();

    var ptr = abi;
    const result = try web3.json.JsonReader.parse(parent_allocator, &ptr, []JsonAbiEntry);
    const entries = @as(*const []AbiEntry, @ptrCast(&result)).*;

    arena.freeList();

    return Abi{
        .entries = entries,
    };
}

/// Decodes a given type from the supplied ABI encoded data.
/// `offset` is the offset in bytes of the argument (should be divisible by 32).
/// `arg_type` is the ABI type of the argument.
/// `T` is the type to coerce the data into.
/// Errors if data does not match expected format or if coercion to given type is not possible.
pub fn decodeArg(allocator: std.mem.Allocator, buffer: []const u8, offset: usize, arg_type: *const web3.AbiType, comptime T: type) !T {
    const TI = @typeInfo(T);

    if (offset >= buffer.len) {
        return error.BufferOverflow;
    }

    switch (TI) {
        .Int => |int_t| {
            switch (int_t.signedness) {
                .unsigned => {
                    switch (arg_type.*) {
                        .uint => |uint| {
                            const arg_u256 = std.mem.readIntBig(u256, buffer[offset..][0..32]);
                            if (uint.bits < 256) {
                                const max_value: u256 = std.math.pow(u256, 2, uint.bits) - 1;
                                if (arg_u256 > max_value) {
                                    return error.IntegerOverflow;
                                }
                            }
                            return @intCast(arg_u256);
                        },
                        else => return error.InvalidCoercion,
                    }
                },
                .signed => {
                    switch (arg_type.*) {
                        .int => |int| {
                            const arg_i256 = std.mem.readIntBig(i256, buffer[offset..][0..32]);
                            if (int.bits < 256) {
                                const max_value: u256 = std.math.pow(i256, 2, int.bits) - 1;
                                if (arg_i256 > max_value) {
                                    return error.IntegerOverflow;
                                }
                                const min_value: i256 = -@as(i256, @intCast(max_value)) - 1;
                                if (arg_i256 < min_value) {
                                    return error.IntegerUnderflow;
                                }
                            }
                            return @intCast(arg_i256);
                        },
                        else => return error.InvalidCoercion,
                    }
                },
            }
        },
        .Struct => |struct_t| {
            _ = struct_t;
            if (T == web3.Address) {
                switch (arg_type.*) {
                    .address => {
                        var val: web3.Address = undefined;
                        @memcpy(&val.raw, buffer[offset + 12 ..][0..20]);
                        return val;
                    },
                    else => return error.InvalidCoercion,
                }
            }
            return error.InvalidCoercion;
        },
        .Bool => {
            const arg_u256 = std.mem.readIntBig(u256, buffer[offset..][0..32]);
            return arg_u256 != 0;
        },
        .Array => |array_t| {
            switch (arg_type.*) {
                .fixed_array => |abi_fixed_array_t| {
                    if (abi_fixed_array_t.size != array_t.len) {
                        return error.InvalidCoercion;
                    }

                    var data_position: usize = @truncate(std.mem.readIntBig(u256, buffer[offset..][0..32]));

                    var val: T = undefined;

                    for (0..array_t.len) |i| {
                        val[i] = try decodeArg(allocator, buffer, data_position + (i * 32), abi_fixed_array_t.child, array_t.child);
                    }

                    return val;
                },
                else => return error.InvalidCoercion,
            }
        },
        else => {
            @compileError("Cannot decode type " ++ @typeName(T));
        },
    }
}

/// Encodes a function signature into the supplied buffer
pub fn encodeFunctionSelectorBuf(out_buffer: []u8, method: []const u8, arg_types: []*const web3.AbiType) !void {
    // Allocate temporary memory to construct the function sig
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var func_sig_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
    defer func_sig_buffer.deinit();

    var writer = func_sig_buffer.writer();

    _ = try writer.write(method);
    try writer.writeByte('(');

    var first: bool = true;
    for (arg_types) |arg_type| {
        if (!first) {
            try writer.writeByte(',');
        }
        first = false;

        try writer.print("{}", .{arg_type});
    }

    try writer.writeByte(')');

    var hash_buffer: [32]u8 = undefined;

    // Hash the function sig
    std.crypto.hash.sha3.Keccak256.hash(func_sig_buffer.items, &hash_buffer, .{});

    // Copy first 4 bytes to the output buffer
    @memcpy(out_buffer[0..4], hash_buffer[0..4]);
}

test "encode" {
    const allocator = std.testing.allocator;
    const assert = std.debug.assert;

    // Boolean
    {
        var encoder = CalldataArgEncoder.init(allocator);
        defer encoder.deinit();

        const abi_type = web3.AbiType{
            .boolean = void{},
        };

        try encoder.append(&abi_type, true);
        try encoder.append(&abi_type, false);

        const data = try encoder.encodeAlloc();
        defer allocator.free(data);

        assert(data[31] == 1);
        assert(data[32 + 31] == 0);
    }
}

test "decode" {
    const allocator = std.testing.allocator;
    const assert = std.debug.assert;

    // Array
    {
        const input = "uint256[3]";

        var typ = try web3.AbiType.fromStringAlloc(allocator, input);
        defer typ.deinit(allocator);

        const data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003";
        const bytes = try std.fmt.hexToBytes(data, hex);

        var output: [3]u256 = undefined;
        output = try decodeArg(allocator, bytes, 0, typ, @TypeOf(output));

        assert(output[0] == 1);
        assert(output[1] == 2);
        assert(output[2] == 3);
    }

    // Boolean
    {
        const input = "bool";

        var typ = try web3.AbiType.fromStringAlloc(allocator, input);
        defer typ.deinit(allocator);

        const data = try allocator.alloc(u8, 32);
        defer allocator.free(data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000001";
        const bytes = try std.fmt.hexToBytes(data, hex);

        var output: bool = undefined;
        output = try decodeArg(allocator, bytes, 0, typ, @TypeOf(output));

        assert(output);
    }
}
