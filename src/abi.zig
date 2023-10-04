const std = @import("std");

const web3 = @import("web3.zig");
const parser_allocator = @import("parser_allocator.zig");

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

    pub const json_def = .{
        .state_mutability = web3.json.JsonDef{
            .field_name = "stateMutability",
        },
    };

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
    // This encoder feels quite hacky because of the way ABI encoding works and
    // because I'd like the API of it to allow the user to dynamically append
    // arguments instead of declaring up front what all the arguments are going to be

    const Self = @This();

    const Word = union(enum) {
        pointer: usize, // Signifies this slot should be a pointer into the dynamic block
        literal: usize, // Signifies the data is at this location in the data buffer
    };

    args: std.ArrayList(Word),
    extra_args: std.ArrayList(Word),

    data: std.ArrayList(u8),

    /// Initialize memory
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .args = std.ArrayList(Word).init(allocator),
            .extra_args = std.ArrayList(Word).init(allocator),
            .data = std.ArrayList(u8).init(allocator),
        };
    }

    /// Frees owned memory
    pub fn deinit(self: *Self) void {
        self.args.clearAndFree();
        self.extra_args.clearAndFree();
        self.data.clearAndFree();
    }

    fn isDynamic(abi_type: *const web3.AbiType) bool {
        switch (abi_type.*) {
            .bytes => return true,
            .string => return true,
            .array => return true,
            .fixed_array => |fixed_array_t| {
                if (fixed_array_t.size == 0) {
                    return false;
                }
                return isDynamic(fixed_array_t.child);
            },
            .tuple => |tuple_t| {
                for (tuple_t) |*t| {
                    if (isDynamic(t)) {
                        return true;
                    }
                }
                return false;
            },
            else => return false,
        }
    }

    fn newSlot(self: *Self) ![]u8 {
        try self.data.ensureUnusedCapacity(32);
        self.data.items.len += 32;
        return self.data.items[self.data.items.len - 32 ..][0..32];
    }

    pub fn append(self: *Self, arg_type: *const web3.AbiType, arg: anytype) !void {
        const ATT = @typeInfo(@TypeOf(arg));
        switch (ATT) {
            .Pointer => |ptr_t| {
                if (ptr_t.size == .Slice) {
                    switch (arg_type.*) {
                        .fixed_array => |fixed_array_t| {
                            if (!isDynamic(arg_type)) {
                                for (0..fixed_array_t.size) |i| {
                                    try self.append(fixed_array_t.child, arg[i]);
                                }
                                return;
                            }
                        },
                        else => {},
                    }
                }
            },
            .Array => |array_t| {
                const slice: []const array_t.child = &arg;
                return self.append(arg_type, slice);
            },
            else => {},
        }
        var word = try self.writeArg(arg_type, arg);
        try self.args.append(word);
    }

    fn writeArg(self: *Self, arg_type: *const web3.AbiType, arg: anytype) !Word {
        const ATT = @typeInfo(@TypeOf(arg));
        switch (ATT) {
            .Array => {
                return self.writeArg(arg_type, arg[0..]);
            },
            .Pointer => |ptr_t| {
                if (ptr_t.size != .Slice) {
                    @compileError("Cannot coerce non-slice pointer");
                }

                switch (arg_type.*) {
                    .bytes => {
                        const offset = try self.writeStatic(arg_type, arg);
                        return Word{ .literal = offset };
                    },
                    else => {
                        const offset = try self.writeDynamic(arg_type, arg);
                        return Word{ .pointer = offset };
                    },
                }
            },
            else => {
                const offset = try self.writeStatic(arg_type, arg);
                return Word{ .literal = offset };
            },
        }
    }

    fn writeDynamic(self: *Self, arg_type: *const web3.AbiType, arg: anytype) !usize {
        const TI = @typeInfo(@TypeOf(arg));

        if (TI == .Pointer and TI.Pointer.child == u8) {
            switch (arg_type.*) {
                .string => {
                    const len_offset = self.data.items.len;
                    const len_buffer = try self.newSlot();
                    std.mem.writeIntBig(u256, len_buffer[0..32], arg.len);
                    try self.extra_args.append(Word{ .literal = len_offset });

                    const slots = try std.math.divCeil(u64, arg.len, 32);

                    var remaining: usize = arg.len;
                    for (0..slots) |i| {
                        const offset = self.data.items.len;
                        const buffer = try self.newSlot();
                        @memset(buffer, 0);
                        const len = @min(32, remaining);
                        @memcpy(buffer[0..len], arg[i * 32 ..][0..len]);
                        try self.extra_args.append(Word{ .literal = offset });
                    }

                    return len_offset;
                },
                else => {},
            }
        }

        const offset = self.data.items.len;
        const len_slot = try self.newSlot();
        std.mem.writeIntBig(u256, len_slot[0..32], arg.len);
        try self.extra_args.append(Word{ .literal = offset });

        for (arg) |item| {
            var word = try self.writeArg(arg_type.getChildType(), item);
            try self.extra_args.append(word);
        }
        return offset;
    }

    fn writeStatic(self: *Self, arg_type: *const web3.AbiType, arg: anytype) !usize {
        const offset = self.data.items.len;
        const buffer = try self.newSlot();

        const ATT = @typeInfo(@TypeOf(arg));
        switch (ATT) {
            .Bool => {
                switch (arg_type.*) {
                    .boolean => {
                        @memset(buffer, 0);
                        if (arg) {
                            buffer[31] = 1;
                        }
                        return offset;
                    },
                    else => return error.InvalidCoercion,
                }
            },
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

                                std.mem.writeIntBig(i256, buffer[0..32], arg);
                                return offset;
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

                                std.mem.writeIntBig(u256, buffer[0..32], arg);
                                return offset;
                            },
                            else => return error.InvalidCoercion,
                        }
                    },
                }
            },
            .Struct => |struct_t| {
                _ = struct_t;
                if (@TypeOf(arg) == web3.Address) {
                    switch (arg_type.*) {
                        .address => {
                            @memset(buffer[32..], 0);
                            @memcpy(buffer[44..][0..20], arg.raw[0..20]);
                            return offset;
                        },
                        else => return error.InvalidCoercion,
                    }
                } else {
                    return error.InvalidCoercion;
                }
            },
            .Pointer => |ptr_t| {
                if (ptr_t.child == u8) {
                    var size: u8 = 0;
                    switch (arg_type.*) {
                        .bytes => |bytes_t| {
                            size = bytes_t.size;
                        },
                        .function => {
                            size = 24;
                        },
                        else => return error.InvalidCoercion,
                    }
                    @memset(buffer, 0);
                    @memcpy(buffer[0..size], arg[0..size]);
                    return offset;
                } else {
                    return error.InvalidCoercion;
                }
            },
            else => return error.InvalidCoercion,
        }
    }

    pub fn getEncodedLength(self: *const Self) usize {
        return (self.args.items.len + self.extra_args.items.len) * 32;
    }

    /// Allocates memory for, then writes the encoded values and returns the result
    pub inline fn encodeAlloc(self: *const Self) ![]u8 {
        var buffer = try self.args.allocator.alloc(u8, self.getEncodedLength());
        _ = try self.encodeBuf(buffer);
        return buffer;
    }

    /// Encodes the values into the supplied buffer
    pub inline fn encodeBuf(self: *const Self, buffer: []u8) !usize {
        var total_size = self.getEncodedLength();

        if (buffer.len < total_size) {
            return error.BufferOverflow;
        }

        var dynamic_start: usize = self.args.items.len * 32;
        var dynamic_offset: usize = dynamic_start;

        for (self.args.items, 0..) |arg, i| {
            switch (arg) {
                .pointer => |ptr| {
                    std.mem.writeIntBig(u256, buffer[i * 32 ..][0..32], dynamic_offset + ptr);
                },
                .literal => |lit| {
                    @memcpy(buffer[i * 32 ..][0..32], self.data.items[lit..][0..32]);
                },
            }
        }
        for (self.extra_args.items, self.args.items.len..) |arg, i| {
            switch (arg) {
                .pointer => |ptr| {
                    std.mem.writeIntBig(u256, buffer[i * 32 ..][0..32], dynamic_offset + ptr);
                },
                .literal => |lit| {
                    @memcpy(buffer[i * 32 ..][0..32], self.data.items[lit..][0..32]);
                },
            }
        }

        return total_size;
    }
};

/// Parses a JSON string into an Abi
pub fn parseJson(allocator: std.mem.Allocator, abi: []const u8) !Abi {
    var arena = parser_allocator.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    var parent_allocator = arena.allocator();

    var ptr = abi;
    const entries = try web3.json.JsonReader.parse(parent_allocator, &ptr, []AbiEntry);

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

    if (offset + 32 > buffer.len) {
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
                .bytes => |bytes_t| {
                    if (array_t.child != u8 or array_t.len != bytes_t.size) {
                        return error.InvalidCoercion;
                    }

                    var val: T = undefined;
                    @memcpy(&val, buffer[offset..][0..bytes_t.size]);
                    return val;
                },
                .function => {
                    if (array_t.child != u8 or array_t.len != 24) {
                        return error.InvalidCoercion;
                    }

                    var val: T = undefined;
                    @memcpy(&val, buffer[offset..][0..24]);
                    return val;
                },
                else => return error.InvalidCoercion,
            }
        },
        .Pointer => |ptr_t| {
            switch (arg_type.*) {
                .string => {
                    if (ptr_t.child != u8 or ptr_t.size != .Slice) {
                        return error.InvalidCoercion;
                    }

                    const len_offset: usize = @intCast(std.mem.readIntBig(u256, buffer[offset..][0..32]));

                    if (len_offset + 64 > buffer.len) {
                        return error.BufferOverflow;
                    }

                    const data_offset = len_offset + 32;

                    const str_len: usize = @intCast(std.mem.readIntBig(u256, buffer[len_offset..][0..32]));

                    if (data_offset + str_len > buffer.len) {
                        return error.BufferOverflow;
                    }

                    const str = buffer[data_offset..][0..str_len];

                    var str_copy = try allocator.alloc(u8, str_len);
                    @memcpy(str_copy, str);
                    return str_copy;
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

    // boolean
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

        const hex = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000";
        const expected_data = try allocator.alloc(u8, hex.len / 2);
        defer allocator.free(expected_data);

        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // fixed array
    {
        var encoder = CalldataArgEncoder.init(allocator);
        defer encoder.deinit();

        var bool_abi_type = web3.AbiType{ .boolean = void{} };
        const array_abi_type = web3.AbiType{ .fixed_array = .{
            .size = 2,
            .child = &bool_abi_type,
        } };

        var bools = [_]bool{ true, false };

        try encoder.append(&array_abi_type, bools);

        const data = try encoder.encodeAlloc();
        defer allocator.free(data);

        const hex = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000";
        const expected_data = try allocator.alloc(u8, hex.len / 2);
        defer allocator.free(expected_data);

        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // dynamic array
    {
        var encoder = CalldataArgEncoder.init(allocator);
        defer encoder.deinit();

        var uint256_abi_type = web3.AbiType{
            .uint = .{ .bits = 256 },
        };
        const array_abi_type = web3.AbiType{
            .array = &uint256_abi_type,
        };

        var uints: [2]u64 = [_]u64{ 123, 456 };

        try encoder.append(&array_abi_type, uints);

        const data = try encoder.encodeAlloc();
        defer allocator.free(data);

        const hex = "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000001c8";
        const expected_data = try allocator.alloc(u8, hex.len / 2);
        defer allocator.free(expected_data);

        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // uint256
    {
        var encoder = CalldataArgEncoder.init(allocator);
        defer encoder.deinit();

        const abi_type = web3.AbiType{
            .uint = .{ .bits = 256 },
        };

        try encoder.append(&abi_type, @as(u256, 123));

        const data = try encoder.encodeAlloc();
        defer allocator.free(data);

        const hex = "000000000000000000000000000000000000000000000000000000000000007b";
        const expected_data = try allocator.alloc(u8, hex.len / 2);
        defer allocator.free(expected_data);

        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // string
    {
        var encoder = CalldataArgEncoder.init(allocator);
        defer encoder.deinit();

        const abi_type = web3.AbiType{
            .string = void{},
        };

        const string: []const u8 = "Hello, world!";

        try encoder.append(&abi_type, string);

        const data = try encoder.encodeAlloc();
        defer allocator.free(data);

        const expected_data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(expected_data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d48656c6c6f2c20776f726c642100000000000000000000000000000000000000";
        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // bytes<M>
    {
        var encoder = CalldataArgEncoder.init(allocator);
        defer encoder.deinit();

        const abi_type = web3.AbiType{
            .bytes = .{ .size = 8 },
        };

        const bytes: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

        try encoder.append(&abi_type, bytes);

        const data = try encoder.encodeAlloc();
        defer allocator.free(data);

        const expected_data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(expected_data);

        const hex = "0102030405060708000000000000000000000000000000000000000000000000";
        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
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

    // String
    {
        const input = "string";

        var typ = try web3.AbiType.fromStringAlloc(allocator, input);
        defer typ.deinit(allocator);

        const data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d48656c6c6f2c20776f726c642100000000000000000000000000000000000000";
        const bytes = try std.fmt.hexToBytes(data, hex);

        var output: []u8 = undefined;
        output = try decodeArg(allocator, bytes, 0, typ, @TypeOf(output));
        defer allocator.free(output);

        assert(std.mem.eql(u8, output, "Hello, world!"));
    }

    // bytes<M>
    {
        const input = "bytes8";

        var typ = try web3.AbiType.fromStringAlloc(allocator, input);
        defer typ.deinit(allocator);

        const data = try allocator.alloc(u8, 32);
        defer allocator.free(data);

        const hex = "0102030405060708000000000000000000000000000000000000000000000000";
        const bytes = try std.fmt.hexToBytes(data, hex);

        var output: [8]u8 = undefined;
        output = try decodeArg(allocator, bytes, 0, typ, @TypeOf(output));

        assert(std.mem.eql(u8, &output, bytes[0..8]));
    }
}
