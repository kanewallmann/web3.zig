const std = @import("std");

const web3 = @import("web3.zig");
const parser_allocator = @import("parser_allocator.zig");

/// Represents an input in an ABI entry
pub const AbiInput = struct {
    name: ?[]const u8,
    type: web3.AbiType,
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
    type: web3.AbiType,

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

    /// Recursively frees owned memory
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
        const allocator = gpa.allocator();
        var func_sig_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
        defer func_sig_buffer.deinit();

        const writer = func_sig_buffer.writer();
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
        const allocator = gpa.allocator();
        var func_sig_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
        defer func_sig_buffer.deinit();

        const writer = func_sig_buffer.writer();
        try self.formatSignature(writer);

        var hash_buffer: [32]u8 = undefined;

        // Hash the function sig
        std.crypto.hash.sha3.Keccak256.hash(func_sig_buffer.items, &hash_buffer, .{});

        return web3.Hash.wrap(hash_buffer);
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
    pub fn findEntry(self: *const Self, method: []const u8, arg_types: []web3.AbiType) !?*web3.abi.AbiEntry {
        const entry: ?*web3.abi.AbiEntry = data: for (self.entries) |*entry| {
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
        } else null;

        return entry;
    }

    /// Finds the first ABI entry with the given method name
    pub fn findFirstEntry(self: *const Self, method: []const u8) !?*web3.abi.AbiEntry {
        const entry: ?*web3.abi.AbiEntry = data: for (self.entries) |*entry| {
            if (entry.name) |entry_name| {
                if (std.mem.eql(u8, method, entry_name)) {
                    break :data entry;
                }
            }
        } else null;

        return entry;
    }
};

/// Check if the given type is a Bytes generic
fn isBytes(comptime T: type) bool {
    // Catch bugs where called at runtime
    if (!@inComptime()) @compileError("isBytes called at runtime");
    const TI = @typeInfo(T);
    if (TI != .@"struct") {
        return false;
    }
    return @hasDecl(T, "__is_bytes");
}

/// Check if the given type is an Indexed generic
fn isIndexed(comptime T: type) bool {
    // Catch bugs where called at runtime
    if (!@inComptime()) @compileError("isIndexed called at runtime");
    const TI = @typeInfo(T);
    if (TI != .@"struct") {
        return false;
    }
    return @hasDecl(T, "__is_indexed");
}

/// Check if the given type is a FixedPoint generic
fn isFixedPoint(comptime T: type) bool {
    // Catch bugs where called at runtime
    if (!@inComptime()) @compileError("isFixedPoint called at runtime");
    const TI = @typeInfo(T);
    if (TI != .@"struct") {
        return false;
    }
    return @hasDecl(T, "__is_fixed_point");
}

/// Encodes calldata per ABI specifications
pub const CalldataArgEncoder = struct {
    const Self = @This();

    data: std.ArrayList(u8),
    fixed_length: usize,
    dynamic_length: usize,
    current_arg: usize,

    /// Encodes the inferred args to a newly allocated buffer prefixed with the given selector
    pub fn encodeWithSelector(allocator: std.mem.Allocator, selector: ?[4]u8, args: anytype) ![]u8 {
        const TI = @typeInfo(@TypeOf(args));
        if (TI != .@"struct" and !TI.Struct.is_tuple) {
            @compileError("Supplied args must be a tuple");
        }

        // Calculate the size of the fixed args
        comptime var fixed_length = 0;
        inline for (TI.@"struct".fields) |field| {
            fixed_length += (comptime try getArgLength(field.type))[0];
        }

        const selector_len: usize = if (selector == null) 0 else 4;

        var self = Self{
            .data = try std.ArrayList(u8).initCapacity(allocator, selector_len + fixed_length),
            .fixed_length = fixed_length,
            .dynamic_length = 0,
            .current_arg = 0,
        };
        errdefer self.data.deinit();

        if (selector != null) {
            self.data.items.len += 4;
            @memcpy(self.data.items[0..4], &selector.?);
        }

        // Make space for fixed args
        self.data.items.len += fixed_length;

        // Loop over each fixed arg and write to buffer
        var i: usize = selector_len;
        inline for (TI.@"struct".fields) |field| {
            i += try self.writeArg(@field(args, field.name), i);
        }

        return self.data.toOwnedSlice();
    }

    /// Encodes the inferred args to a newly allocated buffer prefixed with the computed selector for the given method
    pub fn encodeWithMethod(allocator: std.mem.Allocator, method: ?[]const u8, args: anytype) ![]u8 {
        const selector = try computeSelector(method.?, @TypeOf(args));
        return encodeWithSelector(allocator, selector, args);
    }

    /// Encodes the inferred args to a newly allocated buffer
    pub inline fn encode(allocator: std.mem.Allocator, args: anytype) ![]u8 {
        return Self.encodeWithSelector(allocator, null, args);
    }

    fn writeArg(self: *Self, arg: anytype, offset: usize) !usize {
        const ATT = @typeInfo(@TypeOf(arg));
        switch (ATT) {
            .pointer => |ptr_t| {
                if (ptr_t.size != .Slice) {
                    @compileError("Cannot coerce non-slice pointer");
                }

                try self.writeDynamic(arg, offset);
                return 32;
            },
            .@"struct" => |struct_t| {
                if (@TypeOf(arg) == web3.String or @TypeOf(arg) == web3.ByteArray) {
                    try self.writeStringOrBytes(arg, offset);
                    return 32;
                } else if (comptime isBytes(@TypeOf(arg))) {
                    try self.writeBytesM(arg, offset);
                    return 32;
                }

                if (struct_t.is_tuple) {
                    const length = comptime try getArgLength(@TypeOf(arg));

                    if (length[1]) {
                        try self.writeDynamic(arg, offset);
                        return 32;
                    } else {
                        return self.writeStatic(arg, offset);
                    }
                }
            },
            else => {},
        }

        return try self.writeStatic(arg, offset);
    }

    fn writeDynamic(self: *Self, arg: anytype, offset: usize) !void {
        var buffer = self.data.items[offset..];

        const TI = @typeInfo(@TypeOf(arg));
        switch (TI) {
            .pointer => |ptr_t| {
                const data_offset = self.fixed_length + self.dynamic_length;
                std.mem.writeInt(u256, buffer[0..32], data_offset, .big);

                const arg_size = comptime try getArgLength(ptr_t.child);
                const arr_size = (arg_size[0] * arg.len + 32);

                self.dynamic_length += arr_size;

                try self.data.ensureUnusedCapacity(arr_size);
                self.data.items.len += arr_size;

                buffer = self.data.items[data_offset..];
                std.mem.writeInt(u256, buffer[0..32], arg.len, .big);

                var i: usize = 32;
                for (arg) |child| {
                    i += try self.writeArg(child, data_offset + i);
                }
            },
            .@"struct" => |struct_t| {
                const data_offset = self.fixed_length + self.dynamic_length;
                std.mem.writeInt(u256, buffer[0..32], data_offset, .big);

                var arr_size: usize = 0;
                inline for (struct_t.fields) |field| {
                    arr_size += (comptime try getArgLength(field.type))[0];
                }

                try self.data.ensureUnusedCapacity(arr_size);
                self.data.items.len += arr_size;
                self.dynamic_length += arr_size;

                var i: usize = data_offset;
                inline for (struct_t.fields) |field| {
                    i += try self.writeArg(@field(arg, field.name), i);
                }
            },
            else => @compileError("Cannot encode type " ++ @typeName(@TypeOf(arg))),
        }
    }

    fn writeStatic(self: *Self, arg: anytype, offset: usize) !usize {
        var buffer = self.data.items[offset..];

        if (@TypeOf(arg) == web3.Address) {
            @memset(buffer[32..], 0);
            @memcpy(buffer[12..][0..20], arg.raw[0..20]);
            return 32;
        } else if (@TypeOf(arg) == web3.Function) {
            @memset(buffer[32..], 0);
            @memcpy(buffer[0..24], arg.raw[0..24]);
            return 32;
        }

        const ATT = @typeInfo(@TypeOf(arg));
        switch (ATT) {
            .bool => {
                @memset(buffer, 0);
                if (arg) {
                    buffer[31] = 1;
                }
                return 32;
            },
            .int => |arg_int| {
                switch (arg_int.signedness) {
                    .signed => {
                        const arg_i256: i256 = @intCast(arg);
                        std.mem.writeInt(i256, buffer[0..32], arg_i256, .big);
                    },
                    .unsigned => {
                        const arg_u256: u256 = @intCast(arg);
                        std.mem.writeInt(u256, buffer[0..32], arg_u256, .big);
                    },
                }
                return 32;
            },
            .pointer => |ptr_t| {
                if (ptr_t.child == u8) {
                    const size: u8 = arg.len;
                    @memset(buffer, 0);
                    @memcpy(buffer[0..size], arg[0..size]);
                    return 32;
                } else {
                    unreachable;
                }
            },
            .array => {
                var i: usize = 0;
                for (arg) |child| {
                    i += try self.writeArg(child, offset + i);
                }
                return i;
            },
            .@"struct" => |struct_t| {
                if (!struct_t.is_tuple) {
                    unreachable;
                }
                var i: usize = 0;
                inline for (struct_t.fields) |field| {
                    i += try self.writeArg(@field(arg, field.name), offset + i);
                }
                return i;
            },
            else => @compileError("Cannot encode arg of type " ++ @typeName(@TypeOf(arg))),
        }
    }

    fn writeBytesM(self: *Self, arg: anytype, offset: usize) !void {
        if (arg.raw.len > 32) {
            return error.InvalidBytesLength;
        }
        var buffer = self.data.items[offset..][0..32];
        @memset(buffer, 0);
        @memcpy(buffer[0..arg.raw.len], &arg.raw);
    }

    fn writeStringOrBytes(self: *Self, arg: anytype, offset: usize) !void {
        var buffer = self.data.items[offset..];
        const data_offset = self.fixed_length + self.dynamic_length;
        std.mem.writeInt(u256, buffer[0..32], data_offset, .big);

        const slots = try std.math.divCeil(u64, arg.raw.len, 32);
        const arr_size = (slots + 1) * 32;

        self.dynamic_length += arr_size;

        try self.data.ensureUnusedCapacity(arr_size);
        self.data.items.len += arr_size;

        buffer = self.data.items[data_offset..];
        std.mem.writeInt(u256, buffer[0..32], arg.raw.len, .big);

        buffer = buffer[32..];

        @memset(buffer, 0);
        @memcpy(buffer[0..arg.raw.len], arg.raw);
    }

    fn getArgLength(comptime T: type) !struct { comptime_int, bool } {
        const TI = @typeInfo(T);
        switch (TI) {
            .int, .comptime_int, .bool => {
                return .{ 32, false };
            },
            .@"struct" => |struct_t| {
                switch (T) {
                    web3.Address => return .{ 32, false },
                    web3.Function => return .{ 32, false },
                    web3.String => return .{ 32, true },
                    web3.ByteArray => return .{ 32, true },
                    else => {},
                }
                if (comptime isBytes(T)) {
                    return .{ 32, false };
                }
                if (!struct_t.is_tuple) {
                    @compileError("Cannot encode arg of type " ++ @typeName(T));
                }
                var len: usize = 0;
                inline for (struct_t.fields) |field| {
                    const child_len = try getArgLength(field.type);
                    if (child_len[1]) {
                        return .{ 32, true };
                    }
                    len += child_len[0];
                }
                return .{ len, false };
            },
            .array => |array_t| {
                const child_len = try getArgLength(array_t.child);
                if (child_len[1]) {
                    return .{ 32, true };
                }
                return .{ child_len[0] * array_t.len, false };
            },
            .pointer => {
                return .{ 32, true };
            },
            else => @compileError("Cannot encode arg of type " ++ @typeName(T)),
        }
    }
};

/// Parses a JSON string into an Abi
pub fn parseJson(allocator: std.mem.Allocator, abi: []const u8) !Abi {
    var arena = parser_allocator.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const parent_allocator = arena.allocator();

    var ptr = abi;
    const entries = try web3.json.JsonReader.parse(parent_allocator, &ptr, []AbiEntry);

    arena.freeList();

    return Abi{
        .entries = entries,
    };
}

fn decodeStringOrByteArray(allocator: std.mem.Allocator, buffer: []const u8, offset: usize, comptime T: type) !T {
    const data_offset: usize = @intCast(std.mem.readInt(u256, buffer[offset..][0..32], .big));
    const len: usize = @intCast(std.mem.readInt(u256, buffer[data_offset..][0..32], .big));

    const val: []u8 = try allocator.alloc(u8, len);
    @memcpy(val, buffer[data_offset + 32 ..][0..len]);
    return T.wrap(val);
}

/// Creates a new Struct type based on the given T but with any Indexed children replaced
/// with their child type
fn stripIndexed(comptime T: type) type {
    const TI = @typeInfo(T);

    var fields: [TI.@"struct".fields.len]std.builtin.Type.StructField = undefined;

    for (TI.@"struct".fields, 0..) |field, i| {
        fields[i] = field;

        if (isIndexed(field.type)) {
            fields[i].type = fields[i].type.getType();
        }
    }

    const S: std.builtin.Type = .{
        .@"struct" = .{
            .layout = TI.@"struct".layout,
            .backing_integer = TI.@"struct".backing_integer,
            .decls = TI.@"struct".decls,
            .fields = &fields,
            .is_tuple = TI.@"struct".is_tuple,
        },
    };

    return @Type(S);
}

/// Decodes multiple arguments from the given log inferring types from the given struct type T
pub fn decodeLog(allocator: std.mem.Allocator, log: web3.Log, comptime T: type) !stripIndexed(T) {
    const TI = @typeInfo(T);
    if (TI != .@"struct") {
        @compileError("Supplied type must be a struct");
    }

    var result: stripIndexed(T) = undefined;

    inline for (TI.@"struct".fields, 0..) |field, i| {
        if (comptime isIndexed(field.type)) {
            @field(result, field.name) = try decodeLogArg(allocator, log, i, field.type.getType(), true);
        } else {
            @field(result, field.name) = try decodeLogArg(allocator, log, i, field.type, false);
        }
    }

    return result;
}

/// Decodes a single argument from the given log at specfied offset by inferring type T
pub fn decodeLogArg(allocator: std.mem.Allocator, log: web3.Log, offset: usize, comptime T: type, comptime indexed: bool) !T {
    if (indexed) {
        return try decodeArg(allocator, &log.topics[offset + 1].raw, 0, T);
    } else {
        return try decodeArg(allocator, log.data.raw, (offset - (log.topics.len - 1)) * 32, T);
    }
}

/// Decodes a given type from the supplied ABI encoded data.
/// `offset` is the offset in bytes of the argument (should be divisible by 32).
/// `arg_type` is the ABI type of the argument.
/// `T` is the type to coerce the data into.
/// Errors if data does not match expected format or if coercion to given type is not possible.
pub fn decodeArg(allocator: std.mem.Allocator, buffer: []const u8, offset: usize, comptime T: type) !T {
    const TI = @typeInfo(T);

    if (offset + 32 > buffer.len) {
        return error.BufferOverflow;
    }

    switch (TI) {
        .int => |int_t| {
            switch (int_t.signedness) {
                .unsigned => {
                    const arg_u256 = std.mem.readInt(u256, buffer[offset..][0..32], .big);
                    return @truncate(arg_u256);
                },
                .signed => {
                    const arg_i256 = std.mem.readInt(i256, buffer[offset..][0..32], .big);
                    return @truncate(arg_i256);
                },
            }
        },
        .@"struct" => |struct_t| {
            if (T == web3.Address) {
                var val: web3.Address = undefined;
                @memcpy(&val.raw, buffer[offset + 12 ..][0..20]);
                return val;
            } else if (T == web3.Function) {
                var val: web3.Function = undefined;
                @memcpy(&val.raw, buffer[offset..][0..24]);
                return val;
            } else if (comptime isFixedPoint(T)) {
                return T.wrap(try decodeArg(allocator, buffer, offset, T.getBackingType()));
            } else if (T == web3.ByteArray or T == web3.String) {
                return decodeStringOrByteArray(allocator, buffer, offset, T);
            } else if (comptime isBytes(T)) {
                var val: T = undefined;
                @memcpy(&val.raw, buffer[offset..][0..T.getSize()]);
                return val;
            } else {
                const tuple_offset: usize = @truncate(std.mem.readIntBig(u256, buffer[offset..][0..32]));

                var val: T = undefined;

                inline for (struct_t.fields) |field| {
                    @field(val, field.name) = try decodeArg(allocator, buffer, tuple_offset, field.type);
                }

                return val;
            }
            return error.InvalidCoercion;
        },
        .bool => {
            const arg_u256 = std.mem.readInt(u256, buffer[offset..][0..32], .big);
            return arg_u256 != 0;
        },
        .array => |array_t| {
            const data_position: usize = @truncate(std.mem.readInt(u256, buffer[offset..][0..32], .big));

            var val: T = undefined;

            for (0..array_t.len) |i| {
                val[i] = try decodeArg(allocator, buffer, data_position + (i * 32), array_t.child);
            }

            return val;
        },
        .pointer => |ptr_t| {
            if (ptr_t.child != u8 or ptr_t.size != .Slice) {
                return error.InvalidCoercion;
            }

            const len_offset: usize = @truncate(std.mem.readIntBig(u256, buffer[offset..][0..32]));

            if (len_offset + 64 > buffer.len) {
                return error.BufferOverflow;
            }

            const data_offset = len_offset + 32;

            const str_len: usize = @truncate(std.mem.readIntBig(u256, buffer[len_offset..][0..32]));

            if (data_offset + str_len > buffer.len) {
                return error.BufferOverflow;
            }

            const str = buffer[data_offset..][0..str_len];

            const str_copy = try allocator.alloc(u8, str_len);
            @memcpy(str_copy, str);
            return str_copy;
        },
        else => {
            @compileError("Cannot decode type " ++ @typeName(T));
        },
    }
}

/// Constructs an AbiType by inference of the supplied type T
pub fn abiTypeOf(allocator: std.mem.Allocator, comptime T: type) !web3.AbiType {
    const TI = @typeInfo(T);
    switch (TI) {
        .int => |int_t| {
            if (int_t.bits > 256) {
                @compileError("Cannot get abi type of integer with greater than 256 bits");
            }
            switch (int_t.signedness) {
                .signed => {
                    return web3.AbiType{ .int = .{ .bits = int_t.bits } };
                },
                .unsigned => {
                    return web3.AbiType{ .uint = .{ .bits = int_t.bits } };
                },
            }
        },
        .bool => {
            return web3.AbiType{ .boolean = void{} };
        },
        .@"struct" => |struct_t| {
            switch (T) {
                web3.Address => return web3.AbiType{ .address = void{} },
                web3.String => return web3.AbiType{ .string = void{} },
                web3.ByteArray => return web3.AbiType{ .byte_array = void{} },
                else => {},
            }
            if (comptime isBytes(T)) {
                return web3.AbiType{ .bytes = .{ .size = T.getSize() } };
            }

            // Check for empty tuple
            if (struct_t.fields.len == 0) {
                return web3.AbiType{ .tuple = &.{} };
            }

            if (!struct_t.is_tuple) {
                @compileError("Cannot get abi type of " ++ @typeName(T));
            }

            var types = try std.ArrayList(web3.AbiType).initCapacity(allocator, struct_t.fields.len);
            errdefer types.deinit();

            inline for (struct_t.fields) |field| {
                try types.append(try abiTypeOf(allocator, field.type));
            }

            return web3.AbiType{
                .tuple = try types.toOwnedSlice(),
            };
        },
        .array => |array_t| {
            const child_type = try allocator.create(web3.AbiType);
            errdefer allocator.destroy(child_type);

            child_type.* = try abiTypeOf(allocator, array_t.child);

            return web3.AbiType{
                .fixed_array = .{
                    .child = child_type,
                    .size = array_t.len,
                },
            };
        },
        .pointer => |ptr_t| {
            if (ptr_t.size != .Slice) {
                @compileError("Cannot get abi type of non-slice pointer");
            }

            const child_type = try allocator.create(web3.AbiType);
            errdefer allocator.destroy(child_type);

            child_type.* = try abiTypeOf(allocator, ptr_t.child);

            return web3.AbiType{ .array = child_type };
        },
        else => @compileError("Cannot get abi type of " ++ @typeName(T)),
    }
}

/// Computes the 32 byte event topic from the given event sig
pub fn computeTopicFromSig(sig: []const u8) ![32]u8 {
    @setEvalBranchQuota(100_000);

    // Hash the function sig
    var hash_buffer: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(sig, &hash_buffer, .{});

    return hash_buffer;
}

/// Computes the 4 byte selector from the given function sig
pub fn computeSelectorFromSig(sig: []const u8) ![4]u8 {
    @setEvalBranchQuota(100_000);

    // Hash the function sig
    var hash_buffer: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(sig, &hash_buffer, .{});

    var result: [4]u8 = undefined;
    @memcpy(&result, hash_buffer[0..4]);
    return result;
}

/// Computes the 32 byte event topic based on the given method name
/// and inferred types of the supplied tuple T
pub fn computeTopic(event: []const u8, comptime T: type) ![32]u8 {
    const TI = @typeInfo(T);
    if (TI != .@"struct" and !TI.@"struct".is_tuple) {
        @compileError("Expected tuple type");
    }

    // Allocate temporary memory to construct the function sig
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var func_sig_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
    defer func_sig_buffer.deinit();

    var writer = func_sig_buffer.writer();

    _ = try writer.write(event);
    try writer.writeByte('(');

    const abi_type = try abiTypeOf(allocator, T);
    defer abi_type.deinit(allocator);

    var first = true;
    for (abi_type.tuple) |child| {
        if (!first) {
            try writer.writeByte(',');
        }
        first = false;
        _ = try writer.print("{}", .{child});
    }

    try writer.writeByte(')');

    return computeTopicFromSig(func_sig_buffer.items);
}

/// Computes the 4 byte function selector based on the given method name
/// and inferred types of the supplied tuple T
pub fn computeSelector(method: []const u8, comptime T: type) ![4]u8 {
    const topic = try computeTopic(method, T);
    return topic[0..4].*;
}

test "encode" {
    const allocator = std.testing.allocator;
    const assert = std.debug.assert;

    // boolean
    {
        const data = try CalldataArgEncoder.encode(allocator, .{ true, false });
        defer allocator.free(data);

        const hex = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000";
        const expected_data = try allocator.alloc(u8, hex.len / 2);
        defer allocator.free(expected_data);

        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // uint32
    {
        const data = try CalldataArgEncoder.encode(allocator, .{@as(u32, 123)});
        defer allocator.free(data);

        const hex = "000000000000000000000000000000000000000000000000000000000000007b";
        const expected_data = try allocator.alloc(u8, hex.len / 2);
        defer allocator.free(expected_data);

        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // fixed array
    {
        const bools: [2]bool = [_]bool{ true, false };

        const data = try CalldataArgEncoder.encode(allocator, .{bools});
        defer allocator.free(data);

        const hex = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000";
        const expected_data = try allocator.alloc(u8, hex.len / 2);
        defer allocator.free(expected_data);

        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // dynamic array
    {
        const uints: []const u64 = &[_]u64{ 123, 456 };

        const data = try CalldataArgEncoder.encode(allocator, .{uints});
        defer allocator.free(data);

        const hex = "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000001c8";
        const expected_data = try allocator.alloc(u8, hex.len / 2);
        defer allocator.free(expected_data);

        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // string
    {
        const data = try CalldataArgEncoder.encode(allocator, .{web3.String.wrap("Hello, world!")});
        defer allocator.free(data);

        const expected_data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(expected_data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d48656c6c6f2c20776f726c642100000000000000000000000000000000000000";
        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // bytes
    {
        const data = try CalldataArgEncoder.encode(allocator, .{web3.ByteArray.wrap("Hello, world!")});
        defer allocator.free(data);

        const expected_data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(expected_data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d48656c6c6f2c20776f726c642100000000000000000000000000000000000000";
        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // bytes<M>
    {
        const bytes: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

        const data = try CalldataArgEncoder.encode(allocator, .{web3.Bytes(8).wrap(bytes)});
        defer allocator.free(data);

        const expected_data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(expected_data);

        const hex = "0102030405060708000000000000000000000000000000000000000000000000";
        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // Tuple
    {
        const data = try CalldataArgEncoder.encode(allocator, .{ @as(u32, 100), @as(u32, 200) });
        defer allocator.free(data);

        const expected_data = try allocator.alloc(u8, 32 * 2);
        defer allocator.free(expected_data);

        const hex = "000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000c8";
        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // Dynamic tuple
    {
        const string_a = web3.String.wrap("Hello,");
        const string_b = web3.String.wrap("world!");

        const data = try CalldataArgEncoder.encode(allocator, .{.{ string_a, string_b }});
        defer allocator.free(data);

        const expected_data = try allocator.alloc(u8, 32 * 7);
        defer allocator.free(expected_data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000648656c6c6f2c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006776f726c64210000000000000000000000000000000000000000000000000000";
        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }

    // Tuple array
    {
        const Tuple = struct { u32, u32 };

        const array = [_]Tuple{
            .{ 100, 200 },
            .{ 300, 400 },
        };

        const slice: []const Tuple = &array;

        const data = try CalldataArgEncoder.encode(allocator, .{slice});
        defer allocator.free(data);

        const expected_data = try allocator.alloc(u8, 32 * 6);
        defer allocator.free(expected_data);

        const hex = "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000c8000000000000000000000000000000000000000000000000000000000000012c0000000000000000000000000000000000000000000000000000000000000190";
        const expected_bytes = try std.fmt.hexToBytes(expected_data, hex);

        assert(std.mem.eql(u8, data, expected_bytes));
    }
}

test "decode" {
    const allocator = std.testing.allocator;
    const assert = std.debug.assert;

    // Array
    {
        const data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003";
        const bytes = try std.fmt.hexToBytes(data, hex);

        var output: [3]u256 = undefined;
        output = try decodeArg(allocator, bytes, 0, @TypeOf(output));

        assert(output[0] == 1);
        assert(output[1] == 2);
        assert(output[2] == 3);
    }

    // Boolean
    {
        const data = try allocator.alloc(u8, 32);
        defer allocator.free(data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000001";
        const bytes = try std.fmt.hexToBytes(data, hex);

        var output: bool = undefined;
        output = try decodeArg(allocator, bytes, 0, @TypeOf(output));

        assert(output);
    }

    // String
    {
        const data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d48656c6c6f2c20776f726c642100000000000000000000000000000000000000";
        const bytes = try std.fmt.hexToBytes(data, hex);

        var output: web3.String = undefined;
        output = try decodeArg(allocator, bytes, 0, @TypeOf(output));
        defer output.deinit(allocator);

        assert(std.mem.eql(u8, output.raw, "Hello, world!"));
    }

    // ByteArray
    {
        const data = try allocator.alloc(u8, 32 * 4);
        defer allocator.free(data);

        const hex = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d48656c6c6f2c20776f726c642100000000000000000000000000000000000000";
        const bytes = try std.fmt.hexToBytes(data, hex);

        var output: web3.ByteArray = undefined;
        output = try decodeArg(allocator, bytes, 0, @TypeOf(output));
        defer output.deinit(allocator);

        assert(std.mem.eql(u8, output.raw, "Hello, world!"));
    }

    // bytes<M>
    {
        const data = try allocator.alloc(u8, 32);
        defer allocator.free(data);

        const hex = "0102030405060708000000000000000000000000000000000000000000000000";
        const bytes = try std.fmt.hexToBytes(data, hex);

        var output: web3.Bytes(8) = undefined;
        output = try decodeArg(allocator, bytes, 0, @TypeOf(output));

        assert(std.mem.eql(u8, &output.raw, bytes[0..8]));
    }
}

test "abiTypeOf" {
    const allocator = std.testing.allocator;
    const assert = std.debug.assert;

    {
        const t = try abiTypeOf(allocator, struct { web3.Bytes(32), u32 });
        defer t.deinit(allocator);

        const type_str = try std.fmt.allocPrint(allocator, "{}", .{t});
        defer allocator.free(type_str);

        assert(std.mem.eql(u8, type_str, "(bytes32,uint32)"));
    }

    {
        const t = try abiTypeOf(allocator, [32]u256);
        defer t.deinit(allocator);

        const type_str = try std.fmt.allocPrint(allocator, "{}", .{t});
        defer allocator.free(type_str);

        assert(std.mem.eql(u8, type_str, "uint256[32]"));
    }
}

test "selector" {
    const allocator = std.testing.allocator;
    const assert = std.debug.assert;

    const data = try allocator.alloc(u8, 4);
    defer allocator.free(data);

    {
        const selector = try computeSelector("balanceOf", struct { web3.Address });
        const hex = "70a08231";
        const bytes = try std.fmt.hexToBytes(data, hex);
        assert(std.mem.eql(u8, &selector, bytes[0..4]));
    }

    {
        const selector = try computeSelector("decimals", struct {});
        const hex = "313ce567";
        const bytes = try std.fmt.hexToBytes(data, hex);
        assert(std.mem.eql(u8, &selector, bytes[0..4]));
    }

    {
        const selector = comptime try computeSelectorFromSig("balanceOf(address)");
        const hex = "70a08231";
        const bytes = try std.fmt.hexToBytes(data, hex);
        assert(std.mem.eql(u8, &selector, bytes[0..4]));
    }
}
