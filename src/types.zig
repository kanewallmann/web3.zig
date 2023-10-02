const std = @import("std");
const json = @import("json.zig");
const util = @import("util.zig");

/// Represents an Ethereum address of 20 bytes
pub const Address = struct {
    const Self = @This();

    raw: [20]u8,

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
        return json.JsonWriter.write(self.raw, writer);
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
            var frac_str: [decimals]u8 = undefined;
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

/// Utility type which emits an empty array "[]" to the JsonWriter
pub const EmptyArray = struct {
    pub fn toJson(self: *const EmptyArray, writer: anytype) !usize {
        _ = self;
        return json.JsonWriter.writeLiteral("[]", writer);
    }
};

/// Represents an ABI type. Requires heap allocation as the size of the type can be dynamic (e.g. uint256[3][4]).
/// Reference: https://docs.soliditylang.org/en/v0.8.2/abi-spec.html#types
pub const AbiType = union(enum) {
    const Self = @This();

    // Common typedefs
    pub const uint256 = Self{ .uint = .{ .bits = 256 } };
    pub const uint8 = Self{ .uint = .{ .bits = 8 } };
    pub const int256 = Self{ .int = .{ .bits = 256 } };
    pub const address = Self{ .address = void{} };

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
    /// bytes
    bytes: void,
    /// function
    function: void,
    /// string
    string: void,
    /// (T1,T2,...,Tn)
    tuple: []AbiType,

    /// Recursively frees memory associated with this type
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .array => {
                self.array.deinit(allocator);
            },
            .fixed_array => {
                self.fixed_array.child.deinit(allocator);
            },
            .tuple => {
                for (self.tuple) |*child| {
                    child.deinit(allocator);
                }
                allocator.free(self.tuple);
            },
            else => {},
        }
        allocator.destroy(self);
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
                _ = try writer.write("boolean");
            },
            .string => {
                _ = try writer.write("string");
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
            else => unreachable,
        }
    }

    const fixed_types = std.ComptimeStringMap(Self, .{
        .{ "address", Self{ .address = void{} } },
        .{ "bool", Self{ .boolean = void{} } },
        .{ "function", Self{ .function = void{} } },
        .{ "bytes", Self{ .bytes = void{} } },
        .{ "string", Self{ .string = void{} } },
    });

    /// Parses the provided string and allocates an AbiType based on its contents
    /// Caller should call `deinit` to recursively free memory
    pub fn fromStringAlloc(allocator: std.mem.Allocator, buffer: []const u8) !*Self {
        var child = try allocator.create(AbiType);

        var array_start: usize = 0;
        var child_buffer = buffer;

        for (0..buffer.len) |c| {
            if (buffer[c] == '[') {
                array_start = c;
                child_buffer = buffer[0..c];
                break;
            }
        }

        if (child_buffer.len >= 4 and std.mem.eql(u8, child_buffer[0..4], "uint")) {
            if (child_buffer.len == 4) {
                child.* = Self{ .uint = .{ .bits = 256 } };
            } else {
                var bits = try std.fmt.parseInt(u16, child_buffer[4..], 10);
                child.* = Self{ .uint = .{ .bits = bits } };
            }
        } else if (child_buffer.len >= 3 and std.mem.eql(u8, child_buffer[0..3], "int")) {
            if (child_buffer.len == 3) {
                child.* = Self{ .int = .{ .bits = 256 } };
            } else {
                var bits = try std.fmt.parseInt(u16, child_buffer[3..], 10);
                child.* = Self{ .int = .{ .bits = bits } };
            }
        } else {
            var found = false;
            inline for (fixed_types.kvs) |fixed_type| {
                if (child_buffer.len == fixed_type.key.len and std.mem.eql(u8, child_buffer[0..fixed_type.key.len], fixed_type.key)) {
                    child.* = fixed_type.value;
                    found = true;
                    break;
                }
            }

            if (!found) {
                allocator.destroy(child);
                return error.UnknownType;
            }
        }

        if (array_start == 0) {
            return child;
        }

        var array_end = array_start;

        while (array_end != buffer.len) : (array_end += 1) {
            array_start = array_end;

            if (buffer[array_end] != '[') {
                return error.ParserError;
            }

            array_end += 1;

            for (array_end..buffer.len) |c| {
                if (buffer[c] == ']') {
                    array_end = c;
                    break;
                }
            }

            if (array_end == array_start) {
                allocator.destroy(child);
                return error.ParserError;
            }

            if (array_end == array_start + 1) {
                // Dynamic array
                var array_type = try allocator.create(AbiType);
                array_type.* = Self{
                    .array = child,
                };
                child = array_type;
            } else {
                // Fixed length array
                const size = try std.fmt.parseInt(u16, buffer[array_start + 1 .. array_end], 10);

                var array_type = try allocator.create(AbiType);
                array_type.* = Self{ .fixed_array = .{
                    .size = size,
                    .child = child,
                } };
                child = array_type;
            }
        }

        return child;
    }
};

/// Stores data used to submit a transaction to a provider
pub const TransactionRequest = struct {
    from: Address,
    to: ?Address = null,
    gas: ?u256 = null,
    gas_price: ?u256 = null,
    max_priority_fee_per_gas: ?u256 = null,
    max_fee_per_gas: ?u256 = null,
    value: ?u256 = null,
    data: ?[]const u8 = null,

    /// Deallocates owned memory
    pub fn deinit(self: TransactionRequest, allocator: std.mem.Allocator) void {
        if (self.data) |data| {
            allocator.free(data);
        }
    }
};

/// Represents a pending or mined transaction on Ethereum
pub const Transaction = struct {
    block_hash: ?Hash,
    block_number: ?u64,
    from: Address,
    gas: u256,
    gas_price: ?u256 = null,
    max_priority_fee_per_gas: ?u256 = null,
    max_fee_per_gas: ?u256 = null,
    hash: Hash,
    input: []const u8,
    to: Address,
    transaction_index: u32,
    value: u256,
    v: u8,
    r: u256,
    s: u256,

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
    gasUsed: u256,
    contract_address: ?Address,
    logs: []Log,
    logs_bloom: FixedDataHexString(256),
    type: u8,
    status: u8,

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
        },

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

/// Represents a dynamic array of bytes encoded as a hex string
pub const DataHexString = struct {
    const Self = @This();

    raw: []const u8,

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
        return json.JsonWriter.write(self.raw, writer);
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

        pub fn wrap(raw: []const u8) Self {
            var self: Self = undefined;
            @memcpy(&self.raw, raw[0..size]);
            return self;
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
            return json.JsonWriter.write(&self.raw, writer);
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
            return json.JsonWriter.write(self.raw, writer);
        }

        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            try writer.print("{}", .{self.raw});
        }
    };
}

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

    const input = "uint256[5][10][]";

    var typ = try AbiType.fromStringAlloc(allocator, input);
    defer typ.deinit(allocator);

    var output = try allocator.alloc(u8, input.len);
    defer allocator.free(output);

    var stream = std.io.fixedBufferStream(output);
    var writer = stream.writer();

    try writer.print("{}", .{typ});

    assert(std.mem.eql(u8, output, input));
}
