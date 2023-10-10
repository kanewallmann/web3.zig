const std = @import("std");

const parser_allocator = @import("parser_allocator.zig");

const web3 = @import("web3.zig");
const json = web3.json;

/// Represents an Ethereum address of 20 bytes
pub const Address = struct {
    const Self = @This();

    pub const zero = fromString("0x0000000000000000000000000000000000000000") catch unreachable;

    raw: [20]u8,

    pub inline fn wrap(raw: [20]u8) Self {
        return Self{
            .raw = raw,
        };
    }

    /// Calculates an Ethereum address from the given uncompressed SEC1 encoded public key
    pub fn fromUncompressedSec1(pubkey_bytes: [65]u8) !Self {
        // Hash the pubkey
        var out: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(pubkey_bytes[1..65], &out, .{});

        // Return as address
        return wrap(out[12..32].*);
    }

    /// Calculates an Ethereum address from the given SEC1 encoded public key
    pub fn fromSec1(sec1: []u8) !Self {
        const point = try std.crypto.ecc.Secp256k1.fromSec1(sec1);
        return fromUncompressedSec1(point.toUncompressedSec1());
    }

    /// Creates an Address from a string
    pub fn fromString(str: []const u8) !Self {
        std.debug.assert(str.len == 40 or str.len == 42);

        var _str = str;

        if (str.len == 42) {
            std.debug.assert(std.mem.eql(u8, str[0..2], "0x"));
            _str = _str[2..];
        }

        var self: Self = undefined;
        _ = std.fmt.hexToBytes(self.raw[0..], _str) catch unreachable;
        return self;
    }

    /// Writes the address in JSON
    pub fn toJson(self: *const Self, writer: anytype) !usize {
        return json.JsonWriter.writeHexString(&self.raw, writer);
    }

    /// Format helper
    pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        return writer.print("0x{}", .{std.fmt.fmtSliceHexLower(self.raw[0..])});
    }
};

fn comptimePow(comptime a: comptime_int, comptime b: comptime_int) comptime_int {
    var res = a;
    for (0..b - 1) |_| {
        res *= res;
    }
    return res;
}

/// Provides methods for working with fixed point integers
pub fn FixedPoint(comptime decimals: comptime_int, comptime T: anytype) type {
    return struct {
        const Self = @This();
        pub const __is_fixed_point = void{}; // Used to determine at comptime this is a FixedPoint type
        const one: T = std.math.pow(T, 10, decimals);

        const Double = @Type(std.builtin.Type{
            .Int = .{
                .signedness = @typeInfo(T).Int.signedness,
                .bits = @typeInfo(T).Int.bits * 2,
            },
        });

        raw: T,

        /// Wraps an existing fixed point
        pub inline fn wrap(val: anytype) Self {
            return Self{
                .raw = @intCast(val),
            };
        }

        /// Converts a regular into into a fixed point
        pub inline fn fromInt(val: anytype) Self {
            return Self{
                .raw = @intCast(val * one),
            };
        }

        /// Returns an approximation of this value as a floating point value
        pub fn toFloat(self: Self) f64 {
            return @as(f64, @floatFromInt(self.raw)) / @as(f64, @floatFromInt(comptimePow(10, decimals)));
        }

        pub fn getDecimals() u8 {
            return decimals;
        }

        pub fn getBackingType() type {
            return T;
        }

        // Arithmetic

        pub inline fn add(self: Self, other: anytype) Self {
            if (@TypeOf(other) == Self) {
                return wrap(self.raw + other.raw);
            } else {
                return wrap(self.raw + fromInt(other));
            }
        }

        pub inline fn sub(self: Self, other: anytype) Self {
            if (@TypeOf(other) == Self) {
                return wrap(self.raw - other.raw);
            } else {
                return wrap(self.raw - fromInt(other));
            }
        }

        pub inline fn mul(self: Self, other: anytype) Self {
            if (@TypeOf(other) == Self) {
                const a: Double = @intCast(self.raw);
                const b: Double = @intCast(other.raw);
                return wrap(@divTrunc(a * b, one));
            } else {
                return wrap(self.raw * @as(T, @intCast(other)));
            }
        }

        pub inline fn div(self: Self, other: anytype) Self {
            if (@TypeOf(other) == Self) {
                return wrap(@divTrunc(self.raw * one, other.raw));
            } else {
                return wrap(self.raw / @as(T, @intCast(other)));
            }
        }

        pub inline fn mod(self: Self, other: anytype) Self {
            if (@TypeOf(other) == Self) {
                return wrap(@mod(self.raw, other.raw));
            } else {
                return wrap(@mod(self.raw, fromInt(other)));
            }
        }

        pub inline fn neg(self: Self) Self {
            return wrap(-self.raw);
        }

        // Comparison operators

        pub inline fn eql(self: Self, other: anytype) bool {
            if (@TypeOf(other) == Self) {
                return self.raw == other.raw;
            } else {
                return self.raw == fromInt(other);
            }
        }

        pub inline fn lt(self: Self, other: anytype) bool {
            if (@TypeOf(other) == Self) {
                return self.raw < other.raw;
            } else {
                return self.raw < fromInt(other);
            }
        }

        pub inline fn lte(self: Self, other: anytype) bool {
            if (@TypeOf(other) == Self) {
                return self.raw <= other.raw;
            } else {
                return self.raw <= fromInt(other);
            }
        }

        pub inline fn gte(self: Self, other: anytype) bool {
            if (@TypeOf(other) == Self) {
                return self.raw >= other.raw;
            } else {
                return self.raw >= fromInt(other);
            }
        }

        /// Format helper
        pub fn format(self: Self, comptime _: []const u8, opts: std.fmt.FormatOptions, writer: anytype) !void {
            if (opts.precision) |precision| {
                return self.toStringTrunc(precision, writer);
            } else {
                return self.toString(writer);
            }
        }

        /// Writes this value to the given writer as a string
        pub fn toString(self: Self, writer: anytype) !void {
            const integer = @divFloor(self.raw, one);
            const frac = @rem(self.raw, one);
            return writer.print("{d}.{d}", .{ integer, frac });
        }

        /// Writes this value to the given writer as a string truncted to the requested decimal points
        pub fn toStringTrunc(self: Self, precision: usize, writer: anytype) !void {
            const integer = @divFloor(self.raw, one);
            const frac = @rem(self.raw, one);
            var frac_str: [decimals]u8 = .{0} ** decimals;
            _ = std.fmt.formatIntBuf(&frac_str, frac, 10, .lower, .{});
            try writer.print("{d}.", .{integer});
            _ = try writer.write(frac_str[0..precision]);
        }
    };
}

/// Type def of a FixedPoint(18, u256)
pub const Ether = FixedPoint(18, u256);

/// Wrapper type around a byte array which informs the JSON parser to treat it
/// as a string instead of encoding the bytes in hex
pub const String = struct {
    const Self = @This();

    raw: []const u8,

    /// Wraps existing memory
    pub inline fn wrap(raw: []const u8) Self {
        return Self{
            .raw = raw,
        };
    }

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
    }

    /// Allocates memory and copies string from supplied buffer
    pub fn fromStringAlloc(allocator: std.mem.Allocator, buffer: []const u8) !Self {
        var self = Self{
            .raw = try allocator.alloc(u8, buffer.len),
        };

        if (buffer.len > 0) {
            @memcpy(@constCast(self.raw), buffer);
        }

        return self;
    }

    /// Writes the string to JSON
    pub fn toJson(self: *const Self, writer: anytype) !usize {
        return json.JsonWriter.writeString(self.raw, writer);
    }

    /// Format helper
    pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        return writer.print("{s}", .{self.raw});
    }
};

/// Represents an abi bytes<M> type
pub fn Bytes(comptime size: comptime_int) type {
    if (size == 0 or size > 32) {
        @compileError("Bytes size must be between 1 and 32");
    }
    return struct {
        const Self = @This();
        pub const __is_bytes = void{}; // Used to determine at comptime this is a Bytes type

        raw: [size]u8,

        pub fn getSize() comptime_int {
            return size;
        }

        /// Wraps existing memory
        pub inline fn wrap(raw: [size]u8) Self {
            return Self{
                .raw = raw,
            };
        }
    };
}

/// Represents an abi bytes type
pub const ByteArray = struct {
    const Self = @This();

    raw: []const u8,

    /// Wraps existing memory
    pub inline fn wrap(raw: []const u8) Self {
        return Self{
            .raw = raw,
        };
    }

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
    }
};

/// Represents an abi function type (a 20 byte address followed by a 4 byte selector)
pub const Function = struct {
    const Self = @This();

    raw: [24]u8,

    /// Wraps existing memory
    pub inline fn wrap(raw: [24]u8) Self {
        return Self{
            .raw = raw,
        };
    }

    /// Creates a Function from given address and selector
    pub inline fn wrapParts(address: [20]u8, selector: [4]u8) Self {
        var self: Self = undefined;
        @memcpy(self.raw[0..20], &address);
        @memcpy(self.raw[20..24], &selector);
        return self;
    }

    /// Creates an Address from a string
    pub fn fromString(str: []const u8) !Self {
        std.debug.assert(str.len == 44 or str.len == 46);

        var _str = str;

        if (str.len == 44) {
            std.debug.assert(std.mem.eql(u8, str[0..2], "0x"));
            _str = _str[2..];
        }

        var self: Self = undefined;
        _ = std.fmt.hexToBytes(self.raw[0..], _str) catch unreachable;
        return self;
    }

    /// Writes the address in JSON
    pub fn toJson(self: *const Self, writer: anytype) !usize {
        return json.JsonWriter.write(self.raw, writer);
    }

    /// Format helper
    pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        return writer.print("0x{}", .{std.fmt.fmtSliceHexLower(self.raw[0..])});
    }
};

/// Represents an "indexed" argument for a Solidity event
pub fn Indexed(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const __is_indexed = void{}; // Used to determine at comptime this is an Indexed type

        raw: T,

        pub inline fn wrap(raw: T) Self {
            return Self{
                .raw = raw,
            };
        }

        pub fn getType() type {
            return T;
        }
    };
}

/// Utility type which emits an empty array "[]" to the JsonWriter
pub const EmptyArray = struct {
    pub fn toJson(self: *const EmptyArray, writer: anytype) !usize {
        _ = self;
        return json.JsonWriter.writeLiteral("[]", writer);
    }
};

/// Represents an ABI type.
/// Reference: https://docs.soliditylang.org/en/v0.8.2/abi-spec.html#types
pub const AbiType = union(enum) {
    const Self = @This();

    // Common typedefs
    pub const uint256 = Self{ .uint = .{ .bits = 256 } };
    pub const uint8 = Self{ .uint = .{ .bits = 8 } };
    pub const int256 = Self{ .int = .{ .bits = 256 } };
    pub const address = Self{ .address = void{} };
    pub const boolean = Self{ .boolean = void{} };
    pub const string = Self{ .string = void{} };

    /// uint<M>
    uint: struct {
        bits: u16,
    },
    /// int<M>
    int: struct {
        bits: u16,
    },
    /// address
    address: void,
    /// bool
    boolean: void,
    /// ufixed<M>x<N>
    fixed_uint: struct {
        int_bits: u8,
        frac_bits: u8,
    },
    /// fixed<M>x<N>
    fixed_int: struct {
        int_bits: u8,
        frac_bits: u8,
    },
    /// bytes<M>
    fixed_bytes: struct {
        size: u8,
    },
    /// <type>[M]
    fixed_array: struct {
        size: u16,
        child: *AbiType,
    },
    /// <type>[]
    array: *AbiType,
    /// bytes<M>
    bytes: struct {
        size: u8,
    },
    /// bytes
    byte_array: void,
    /// function
    function: void,
    /// string
    string: void,
    /// (T1,T2,...,Tn)
    tuple: []AbiType,

    pub fn getChildType(self: Self) AbiType {
        switch (self) {
            .fixed_array => |fixed_array_t| return fixed_array_t.child.*,
            .array => |array_t| return array_t.*,
            else => @panic("Not an array"),
        }
    }

    pub fn isDynamic(self: Self) bool {
        switch (self) {
            .bytes => return true,
            .string => return true,
            .array => return true,
            .fixed_array => |fixed_array_t| {
                if (fixed_array_t.size == 0) {
                    return false;
                }
                return isDynamic(fixed_array_t.child.*);
            },
            .tuple => |tuple_t| {
                for (tuple_t) |*t| {
                    if (isDynamic(t.*)) {
                        return true;
                    }
                }
                return false;
            },
            else => return false,
        }
    }

    /// Recursively frees memory associated with this type
    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        switch (self) {
            .array => {
                self.array.deinit(allocator);
                allocator.destroy(self.array);
            },
            .fixed_array => {
                self.fixed_array.child.deinit(allocator);
                allocator.destroy(self.fixed_array.child);
            },
            .tuple => {
                for (self.tuple) |*child| {
                    child.deinit(allocator);
                }
                allocator.free(self.tuple);
            },
            else => {},
        }
    }

    /// Format helper
    pub fn format(self: Self, comptime fmt: []const u8, opts: std.fmt.FormatOptions, writer: anytype) !void {
        switch (self) {
            .uint => |uint| {
                _ = try writer.write("uint");
                try std.fmt.formatInt(uint.bits, 10, .lower, .{}, writer);
            },
            .int => |uint| {
                _ = try writer.write("int");
                try std.fmt.formatInt(uint.bits, 10, .lower, .{}, writer);
            },
            .address => {
                _ = try writer.write("address");
            },
            .boolean => {
                _ = try writer.write("bool");
            },
            .string => {
                _ = try writer.write("string");
            },
            .function => {
                _ = try writer.write("function");
            },
            .bytes => |bytes_t| {
                _ = try writer.write("bytes");
                try std.fmt.formatInt(bytes_t.size, 10, .lower, .{}, writer);
            },
            .array => |array_t| {
                try array_t.format(fmt, opts, writer);
                _ = try writer.write("[]");
            },
            .fixed_array => |fixed_array_t| {
                try fixed_array_t.child.format(fmt, opts, writer);
                try writer.writeByte('[');
                try std.fmt.formatInt(fixed_array_t.size, 10, .lower, .{}, writer);
                try writer.writeByte(']');
            },
            .tuple => |tuple_t| {
                try writer.writeByte('(');
                var first: bool = true;
                for (tuple_t) |child_t| {
                    if (!first) {
                        try writer.writeByte(',');
                    }
                    first = false;
                    try child_t.format(fmt, opts, writer);
                }
                try writer.writeByte(')');
            },
            else => unreachable,
        }
    }

    const fixed_types = std.ComptimeStringMap(Self, .{
        .{ "address", Self{ .address = void{} } },
        .{ "bool", Self{ .boolean = void{} } },
        .{ "function", Self{ .function = void{} } },
        .{ "string", Self{ .string = void{} } },
    });

    /// Parses the provided string and allocates an AbiType based on its contents
    /// Return value may own allocated memory in the case of a dynamic type (e.g. uint256[3][4]).
    /// User should call deinit when type is no longer needed to potentially free any owned memory.
    pub fn fromStringAlloc(allocator: std.mem.Allocator, buffer: []const u8) !Self {
        var local_buffer = buffer;

        var arena = parser_allocator.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        var parent_allocator = arena.allocator();

        const result = parse(parent_allocator, &local_buffer);
        arena.freeList();
        return result;
    }

    fn parseInt(buffer: *[]const u8) !u32 {
        var i: usize = 0;
        while (i < buffer.len) : (i += 1) {
            if (!std.ascii.isDigit(buffer.*[i])) {
                break;
            }
        }
        const int = try std.fmt.parseInt(u32, buffer.*[0..i], 10);
        buffer.* = buffer.*[i..];
        return int;
    }

    fn parse(allocator: std.mem.Allocator, _buffer: *[]const u8) !Self {
        var buffer = _buffer.*;
        defer _buffer.* = buffer;

        var child: Self = undefined;

        if (buffer[0] == '(') {
            var fields = try std.ArrayList(AbiType).initCapacity(allocator, 1);

            var i: usize = 1;
            _ = i;

            buffer = buffer[1..];

            while (buffer.len > 0) {
                try fields.append(try parse(allocator, &buffer));

                if (buffer.len == 0) {
                    return error.ParserError;
                }

                switch (buffer[0]) {
                    ',' => {
                        buffer = buffer[1..];
                    },
                    ')' => {
                        break;
                    },
                    else => return error.ParserError,
                }
            }

            if (buffer[0] != ')') {
                return error.ParserError;
            }

            buffer = buffer[1..];

            child = Self{
                .tuple = try fields.toOwnedSlice(),
            };

            if (buffer.len == 0) {
                return child;
            }
        } else if (buffer.len >= 4 and std.mem.eql(u8, buffer[0..4], "uint")) {
            buffer = buffer[4..];
            var bits: u16 = 256;
            if (buffer.len > 0 and std.ascii.isDigit(buffer[0])) {
                bits = @intCast(try parseInt(&buffer));
            }
            child = Self{ .uint = .{ .bits = bits } };
        } else if (buffer.len >= 3 and std.mem.eql(u8, buffer[0..3], "int")) {
            buffer = buffer[3..];
            var bits: u16 = 256;
            if (buffer.len > 0 and std.ascii.isDigit(buffer[0])) {
                bits = @intCast(try parseInt(&buffer));
            }
            child = Self{ .int = .{ .bits = bits } };
        } else if (buffer.len >= 5 and std.mem.eql(u8, buffer[0..5], "bytes")) {
            buffer = buffer[5..];
            if (buffer.len > 0 and std.ascii.isDigit(buffer[0])) {
                const bytes: u8 = @intCast(try parseInt(&buffer));
                if (bytes == 0 or bytes > 32) {
                    return error.ParserError;
                }
                child = Self{ .bytes = .{ .size = bytes } };
            } else {
                child = Self{ .byte_array = void{} };
            }
        } else {
            var found = false;
            inline for (fixed_types.kvs) |fixed_type| {
                if (buffer.len >= fixed_type.key.len and std.mem.eql(u8, buffer[0..fixed_type.key.len], fixed_type.key)) {
                    child = fixed_type.value;
                    buffer = buffer[fixed_type.key.len..];
                    found = true;
                    break;
                }
            }

            if (!found) {
                return error.UnknownType;
            }
        }

        if (buffer.len == 0) {
            return child;
        }

        if (buffer[0] == '[') {
            while (buffer.len > 0) {
                if (buffer[0] != '[') {
                    break;
                }

                buffer = buffer[1..];

                var size: usize = 0;
                if (buffer[0] != ']') {
                    size = try parseInt(&buffer);

                    if (size == 0) {
                        return error.ParserError;
                    }

                    if (buffer[0] != ']') {
                        return error.ParserError;
                    }
                }

                buffer = buffer[1..];

                if (size == 0) {
                    // Dynamic array
                    var child_ptr = try allocator.create(AbiType);
                    child_ptr.* = child;
                    child = Self{
                        .array = child_ptr,
                    };
                } else {
                    var child_ptr = try allocator.create(AbiType);
                    child_ptr.* = child;
                    child = Self{
                        .fixed_array = .{
                            .size = @intCast(size),
                            .child = child_ptr,
                        },
                    };
                }
            }
        }

        return child;
    }
};

/// Represents an unmined Ethereum transaction
pub const TransactionRequest = struct {
    const Self = @This();

    chain_id: ?u256 = null,
    from: ?Address = null,
    to: ?Address = null,
    gas: ?u256 = null,
    gas_price: ?u256 = null,
    max_priority_fee_per_gas: ?u256 = null,
    max_fee_per_gas: ?u256 = null,
    nonce: ?u256 = null,
    value: ?u256 = null,
    data: ?DataHexString = null,
    v: ?u256 = null,
    r: ?u256 = null,
    s: ?u256 = null,

    pub const json_def = .{
        .chain_id = json.JsonDef{
            .field_name = "chainId",
        },
        .gas_price = json.JsonDef{
            .field_name = "gasPrice",
        },
        .max_priority_fee_per_gas = json.JsonDef{
            .field_name = "maxPriorityFeePerGas",
        },
        .max_fee_per_gas = json.JsonDef{
            .field_name = "maxFeePerGas",
        },
    };

    /// Determines the transaction type by the existence of `max_priority_fee_per_gas`
    pub fn getType(self: TransactionRequest) u32 {
        if (self.max_priority_fee_per_gas != null) {
            return 2;
        } else {
            return 0;
        }
    }

    /// Deallocates owned memory
    pub fn deinit(self: TransactionRequest, allocator: std.mem.Allocator) void {
        if (self.data) |data| {
            allocator.free(data.raw);
        }
    }

    /// Adds the given signature to this TransactionRequest making it a signed transaction request
    pub fn addSignature(self: *TransactionRequest, signature: web3.ecdsa.Signature) void {
        self.v = signature.v;
        self.r = signature.r;
        self.s = signature.s;
    }

    /// Encodes in the format expected by eth_signTransaction. The result is either a "LegacyTransaction"
    /// or an EIP-2718 "Typed Transaction" depending on the inferred transaction type.
    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
        defer buffer.deinit();

        var writer = buffer.writer();

        switch (self.getType()) {
            0 => {
                // "LegacyTransaction"
                if (self.nonce == null or self.gas_price == null or self.value == null or self.gas == null) {
                    return error.MissingFields;
                }

                try web3.rlp.RlpEncoder.write(.{
                    self.nonce.?,
                    self.gas_price.?,
                    self.gas.?,
                    if (self.to == null) web3.Address.zero.raw else self.to.?.raw,
                    if (self.value == null) 0 else self.value.?,
                    if (self.data == null) &.{} else self.data.?.raw,
                    if (self.v != null) self.v else if (self.chain_id != null) self.chain_id else 0,
                    if (self.r == null) 0 else self.r,
                    if (self.s == null) 0 else self.s,
                }, writer);
            },
            2 => {
                // EIP-1559 Transaction
                if (self.chain_id == null or self.nonce == null or self.max_priority_fee_per_gas == null or self.max_fee_per_gas == null or self.gas == null) {
                    return error.MissingFields;
                }

                try writer.writeByte(2);
                try web3.rlp.RlpEncoder.write(.{
                    self.chain_id.?,
                    self.nonce.?,
                    self.max_priority_fee_per_gas.?,
                    self.max_fee_per_gas.?,
                    self.gas.?,
                    if (self.to == null) web3.Address.zero.raw else self.to.?.raw,
                    if (self.value == null) 0 else self.value.?,
                    if (self.data == null) &.{} else self.data.?.raw,
                    if (self.v != null) self.v else if (self.chain_id != null) self.chain_id else 0,
                    if (self.r == null) 0 else self.r,
                    if (self.s == null) 0 else self.s,
                }, writer);
            },
            else => return error.UnknownTransactionType,
        }

        return buffer.toOwnedSlice();
    }
};

/// Represents a pending or mined transaction on Ethereum
pub const Transaction = struct {
    block_hash: ?Hash = null,
    block_number: ?u64 = null,
    from: Address,
    gas: u256,
    gas_price: ?u256 = null,
    max_priority_fee_per_gas: ?u256 = null,
    max_fee_per_gas: ?u256 = null,
    nonce: u64,
    hash: ?Hash = null,
    input: []const u8,
    to: ?Address = null,
    transaction_index: ?u32 = null,
    type: u8,
    value: u256,
    v: u256,
    r: u256,
    s: u256,

    pub const json_def = .{
        .block_hash = json.JsonDef{
            .field_name = "blockHash",
        },
        .block_number = json.JsonDef{
            .field_name = "blockNumber",
        },
        .gas_price = json.JsonDef{
            .field_name = "gasPrice",
        },
        .max_priority_fee_per_gas = json.JsonDef{
            .field_name = "maxPriorityFeePerGas",
        },
        .max_fee_per_gas = json.JsonDef{
            .field_name = "maxFeePerGas",
        },
        .transaction_index = json.JsonDef{
            .field_name = "transactionIndex",
        },
    };

    /// Deallocates owned memory
    pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
        allocator.free(self.input);
    }
};

/// Represents an Ethereum transaction receipt
pub const TransactionReceipt = struct {
    transaction_hash: Hash,
    transaction_index: u32,
    block_hash: Hash,
    block_number: u64,
    from: Address,
    to: Address,
    cumulative_gas_used: u256,
    effective_gas_price: u256,
    gas_used: u256,
    contract_address: ?Address,
    logs: []Log,
    logs_bloom: FixedDataHexString(256),
    type: u8,
    status: u8,

    pub const json_def = .{
        .transaction_hash = json.JsonDef{
            .field_name = "transactionHash",
        },
        .transaction_index = json.JsonDef{
            .field_name = "transactionIndex",
        },
        .block_hash = json.JsonDef{
            .field_name = "blockHash",
        },
        .block_number = json.JsonDef{
            .field_name = "blockNumber",
        },
        .cumulative_gas_used = json.JsonDef{
            .field_name = "cumulativeGasUsed",
        },
        .effective_gas_price = json.JsonDef{
            .field_name = "effectiveGasPrice",
        },
        .gas_used = json.JsonDef{
            .field_name = "gasUsed",
        },
        .contract_address = json.JsonDef{
            .field_name = "contractAddress",
        },
        .logs_bloom = json.JsonDef{
            .field_name = "logsBloom",
        },
    };

    /// Deallocates owned memory
    pub fn deinit(self: *TransactionReceipt, allocator: std.mem.Allocator) void {
        for (self.logs) |*log| {
            log.deinit(allocator);
        }
        allocator.free(self.logs);
    }
};

/// Represents an Ethereum log
pub const Log = struct {
    removed: bool,
    log_index: ?u32,
    transaction_index: ?u32,
    transaction_hash: ?Hash,
    block_hash: ?Hash,
    block_number: ?u64,
    address: Address,
    data: DataHexString,
    topics: []Hash,

    pub const json_def = .{
        .log_index = json.JsonDef{
            .field_name = "logIndex",
        },
        .transaction_index = json.JsonDef{
            .field_name = "transactionIndex",
        },
        .transaction_hash = json.JsonDef{
            .field_name = "transactionHash",
        },
        .block_hash = json.JsonDef{
            .field_name = "blockHash",
        },
        .block_number = json.JsonDef{
            .field_name = "blockNumber",
        },
    };

    /// Frees owned memory
    pub inline fn deinit(self: *Log, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
        allocator.free(self.topics);
    }
};

/// Utility wrapper around a dynamic array of Logs
pub const Logs = struct {
    raw: []Log,

    /// Frees owned memory
    pub fn deinit(self: Logs, allocator: std.mem.Allocator) void {
        for (self.raw) |*log| {
            log.deinit(allocator);
        }
        allocator.free(self.raw);
    }
};

/// Represents an Ethereum block. There are two versions of this type,
/// one where the transactions field is an array of hashes and another
/// where the transactions field is an array of Transaction structs
pub fn Block(comptime full_transactions: bool) type {
    const TransactionType = if (full_transactions) Transaction else Hash;

    return struct {
        const Self = @This();

        difficulty: u256,
        extra_data: DataHexString,
        gas_limit: u256,
        gas_used: u256,
        hash: ?Hash,
        logs_bloom: FixedDataHexString(256),
        miner: Address,
        mix_hash: Hash,
        nonce: ?FixedDataHexString(8),
        number: ?u64,
        parent_hash: Hash,
        receipts_root: Hash,
        sha3_uncles: Hash,
        size: u64,
        state_root: Hash,
        timestamp: u64,
        total_difficulty: u256,
        transactions_root: Hash,
        withdrawals_root: Hash,
        transactions: []TransactionType,
        uncles: []Hash,
        withdrawals: []struct {
            index: u64,
            validator_index: u64,
            address: Address,
            amount: u64,

            pub const json_def = .{
                .validator_index = json.JsonDef{
                    .field_name = "validatorIndex",
                },
            };
        },

        pub const json_def = .{
            .extra_data = json.JsonDef{
                .field_name = "extraData",
            },
            .gas_limit = json.JsonDef{
                .field_name = "gasLimit",
            },
            .gas_used = json.JsonDef{
                .field_name = "gasUsed",
            },
            .logs_bloom = json.JsonDef{
                .field_name = "logsBloom",
            },
            .mix_hash = json.JsonDef{
                .field_name = "mixHash",
            },
            .parent_hash = json.JsonDef{
                .field_name = "parentHash",
            },
            .receipts_root = json.JsonDef{
                .field_name = "receiptsRoot",
            },
            .sha3_uncles = json.JsonDef{
                .field_name = "sha3Uncles",
            },
            .state_root = json.JsonDef{
                .field_name = "stateRoot",
            },
            .total_difficulty = json.JsonDef{
                .field_name = "totalDifficulty",
            },
            .transactions_root = json.JsonDef{
                .field_name = "transactionsRoot",
            },
            .withdrawals_root = json.JsonDef{
                .field_name = "withdrawalsRoot",
            },
        };

        /// Deallocates owned memory
        pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
            self.extra_data.deinit(allocator);
            if (full_transactions) {
                for (self.transactions) |tx| {
                    tx.deinit(allocator);
                }
            }
            allocator.free(self.transactions);
            allocator.free(self.uncles);
            allocator.free(self.withdrawals);
        }
    };
}

/// Information about the sync status of an execution client
pub const SyncData = struct {
    starting_block: ?u64 = null,
    current_block: ?u64 = null,
    highest_block: ?u64 = null,

    pub const json_def = .{
        .starting_block = json.JsonDef{
            .field_name = "startingBlock",
        },
        .current_block = json.JsonDef{
            .field_name = "currentBlock",
        },
        .highest_block = json.JsonDef{
            .field_name = "highestBlock",
        },
    };
};

/// Whether an execution client is syncing and if so, information about
/// its current status
pub const SyncStatus = union(enum) {
    not_syncing: void,
    syncing: SyncData,
};

/// Refers to a block tag ("latest", "earliest", "pending") or a specific block number
pub const BlockTag = union(enum) {
    number: u64,
    tag: enum { earliest, latest, safe, finalized, pending },
};

/// Contains the optional values available when making a contract call
pub const CallOptions = struct {
    from: ?Address = null,
    value: ?u256 = null,
    gas: ?u256 = null,
    block_tag: ?BlockTag = null,
    tx_type: union(enum) {
        legacy: struct {
            gas_price: ?u256 = null,
        },
        eip1559: struct {
            max_priority_fee_per_gas: ?u256 = null,
            max_fee_per_gas: ?u256 = null,
        },
    } = .{ .eip1559 = .{} },
};

/// Represents a dynamic array of bytes encoded as a hex string
pub const DataHexString = struct {
    const Self = @This();

    raw: []const u8,

    pub fn wrap(raw: []const u8) Self {
        return Self{
            .raw = raw,
        };
    }

    /// Frees the wrapped memory
    pub inline fn deinit(self: Self, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
    }

    /// Parses a hex string from a buffer and allocates memory to hold the result
    pub fn fromStringAlloc(allocator: std.mem.Allocator, str: []const u8) !Self {
        var _str = str;

        if (str.len >= 2 and std.mem.eql(u8, str[0..2], "0x")) {
            _str = _str[2..];
        }

        var self = Self{
            .raw = try allocator.alloc(u8, _str.len / 2),
        };

        if (_str.len > 0) {
            _ = try std.fmt.hexToBytes(@constCast(self.raw[0..]), _str);
        }

        return self;
    }

    /// Writes the wrapped byte array to JSON
    pub fn toJson(self: *const Self, writer: anytype) !usize {
        return json.JsonWriter.writeHexString(self.raw, writer);
    }

    /// Format helper
    pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        return writer.print("0x{}", .{std.fmt.fmtSliceHexLower(self.raw[0..])});
    }
};

/// Represents a fixed sized array of bytes encoded in a hex string
pub fn FixedDataHexString(comptime size: comptime_int) type {
    return struct {
        const Self = @This();

        raw: [size]u8,

        pub fn wrap(raw: [size]u8) Self {
            return Self{
                .raw = raw,
            };
        }

        pub fn fromString(str: []const u8) !Self {
            var _str = str;

            if (str.len >= 2 and std.mem.eql(u8, str[0..2], "0x")) {
                _str = _str[2..];
            }

            var self: Self = undefined;

            if (_str.len > 0) {
                _ = try std.fmt.hexToBytes(self.raw[0..], _str);
            }

            return self;
        }

        pub fn toJson(self: *const Self, writer: anytype) !usize {
            return json.JsonWriter.writeHexString(&self.raw, writer);
        }

        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            return writer.print("0x{}", .{std.fmt.fmtSliceHexLower(self.raw[0..])});
        }
    };
}

/// A 32 byte hash. Type def of FixedDataHexString(32)
pub const Hash = FixedDataHexString(32);

/// Represents an integer encoded into a hex string
pub fn IntHexString(comptime T: type) type {
    return struct {
        const Self = @This();

        raw: T,

        pub inline fn wrap(val: T) Self {
            return Self{
                .raw = val,
            };
        }

        pub fn fromString(str: []const u8) !Self {
            var _str = str;

            if (str.len >= 2 and std.mem.eql(u8, str[0..2], "0x")) {
                _str = _str[2..];
            }

            if (_str.len > 0) {
                return Self{
                    .raw = try std.fmt.parseInt(T, _str, 16),
                };
            }

            return Self{ .raw = 0 };
        }

        pub fn toJson(self: *const Self, writer: anytype) !usize {
            return json.JsonWriter.writeHexInt(self.raw, writer);
        }

        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            try writer.print("{}", .{self.raw});
        }
    };
}

/// Used as a hint to provider for fee estimation
pub const FeeEstimateSpeed = enum { low, average, high };

/// An estimate of fees for an eip-1559 transaction
pub const FeeEstimate = struct {
    max_fee_per_gas: u256,
    max_priority_fee_per_gas: u256,
};

test "fixed point" {
    const assert = std.debug.assert;

    {
        const one_hundred_fp2 = FixedPoint(2, u64).wrap(10000);
        const two_hundred_fp2 = FixedPoint(2, u64).wrap(20000);
        const two_fp2 = FixedPoint(2, u64).wrap(200);

        assert(one_hundred_fp2.mul(2).eql(two_hundred_fp2));
        assert(one_hundred_fp2.mul(two_fp2).eql(two_hundred_fp2));
        assert(two_hundred_fp2.div(two_fp2).eql(one_hundred_fp2));
        assert(one_hundred_fp2.add(one_hundred_fp2).eql(two_hundred_fp2));
    }

    {
        const neg_one_hundred_fp2 = FixedPoint(2, i64).wrap(-10000);
        const neg_two_hundred_fp2 = FixedPoint(2, i64).wrap(-20000);
        const two_fp2 = FixedPoint(2, i64).wrap(200);
        const zero_fp2 = FixedPoint(2, i64).wrap(0);

        assert(neg_one_hundred_fp2.mul(2).eql(neg_two_hundred_fp2));
        assert(neg_one_hundred_fp2.mul(two_fp2).eql(neg_two_hundred_fp2));
        assert(neg_two_hundred_fp2.div(two_fp2).eql(neg_one_hundred_fp2));
        assert(neg_one_hundred_fp2.add(neg_one_hundred_fp2).eql(neg_two_hundred_fp2));
        assert(neg_one_hundred_fp2.sub(neg_one_hundred_fp2).eql(zero_fp2));
        assert(neg_one_hundred_fp2.add(neg_one_hundred_fp2.neg()).eql(zero_fp2));
    }
}

test "type parsing" {
    const allocator = std.testing.allocator;
    const assert = std.debug.assert;

    const inputs = [_][]const u8{
        "uint256[5][10][]",
        "bytes32",
        "int256[]",
        "address",
        "bool",
        "bytes32[3]",
        "bytes32[3]",
        "function",
        "((uint256,int256),bool,bool)",
        "(uint256,int256)[5]",
    };

    for (inputs) |input| {
        var typ = try AbiType.fromStringAlloc(allocator, input);
        defer typ.deinit(allocator);

        var output = try allocator.alloc(u8, input.len);
        defer allocator.free(output);

        var stream = std.io.fixedBufferStream(output);
        var writer = stream.writer();

        try writer.print("{}", .{typ});

        assert(std.mem.eql(u8, output, input));
    }
}

test "transaction" {
    const allocator = std.testing.allocator;
    const assert = std.debug.assert;
    var hex: [1024]u8 = undefined;

    // EIP-1557 (Type 2)
    {
        const tx_req = TransactionRequest{
            .chain_id = 1,
            .nonce = 123,
            .max_priority_fee_per_gas = 100,
            .max_fee_per_gas = 500,
            .gas = 10000000,
            .value = 0,
            .data = DataHexString.wrap(&.{}),
        };
        const tx = try tx_req.encode(allocator);
        defer allocator.free(tx);

        const bytes = try std.fmt.hexToBytes(&hex, "02e4017b648201f4839896809400000000000000000000000000000000000000008080018080");
        assert(std.mem.eql(u8, bytes, tx));
    }

    // Legacy
    {
        const tx_req = TransactionRequest{
            .chain_id = 1,
            .nonce = 123,
            .gas_price = 100,
            .gas = 10000000,
            .value = 500000000,
            .data = DataHexString.wrap(&.{}),
        };
        const tx = try tx_req.encode(allocator);
        defer allocator.free(tx);

        const bytes = try std.fmt.hexToBytes(&hex, "e47b6483989680940000000000000000000000000000000000000000841dcd650080018080");
        assert(std.mem.eql(u8, bytes, tx));
    }
}
