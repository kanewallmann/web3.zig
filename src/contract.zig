const std = @import("std");

const web3 = @import("web3.zig");

/// Represents the return value of a contract call
pub const ReturnValues = struct {
    const Self = @This();

    abi_entry: *web3.abi.AbiEntry,
    data: []const u8,

    /// Retreives a value at the given position and attempts to coerce it into the supplied type
    /// Errors if the position supplied is greater than the number of return arguments or coercion fails.
    pub fn get(self: *const Self, allocator: std.mem.Allocator, position: usize, comptime T: type) !T {
        if (self.abi_entry.outputs) |outputs| {
            if (position > outputs.len - 1) {
                return error.Overflow;
            }
            return web3.abi.decodeArg(allocator, self.data, position * 32, outputs[position].type, T);
        }

        return error.Overflow;
    }

    /// Retreives a value identified by the given name.
    /// Errors if the ABI entry does not contain a return value with that name or coercion fails.
    pub fn getNamed(self: *const Self, allocator: std.mem.Allocator, name: []const u8, comptime T: type) !T {
        if (self.abi_entry.outputs) |outputs| {
            for (outputs, 0..) |output, i| {
                if (output.name) |output_name| {
                    if (std.mem.eql(u8, output_name, name)) {
                        return web3.abi.decodeArg(allocator, self.data, i * 32, output.type, T);
                    }
                }
            }

            return error.NotFound;
        }

        return error.NotFound;
    }
};

/// Abstraction around Ethereum contracts (incomplete)
pub const Contract = struct {
    const Self = @This();

    pub const CallOptions = struct {
        from: web3.Address,
        value: ?u256 = null,
        gas: ?u256 = null,
        block_tag: ?web3.BlockTag = null,
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

    allocator: std.mem.Allocator,
    abi: web3.abi.Abi,
    address: web3.Address,
    provider: web3.Provider,

    /// Intializes a new contract
    pub fn init(allocator: std.mem.Allocator, address: web3.Address, contract_abi: web3.abi.Abi, provider: web3.Provider) Self {
        return Self{
            .allocator = allocator,
            .address = address,
            .abi = contract_abi,
            .provider = provider,
        };
    }

    /// Calls the supplied method on the contract with the given args.
    /// If multiple methods exist with the same name, the first one in the ABI is used.
    pub fn call(self: *const Self, method: []const u8, args: anytype, opts: CallOptions) !ReturnValues {
        const entry = try self.abi.findFirstEntry(method);

        if (entry == null) {
            return error.NoMatchingMethod;
        }

        return self.callEntry(entry.?, args, opts);
    }

    /// Finds a method with matching name and args and calls it on the contract
    pub fn callOverloaded(self: *const Self, method: []const u8, arg_types: []const web3.AbiType, args: anytype, opts: CallOptions) !ReturnValues {
        std.debug.assert(arg_types.len == args.len);
        const entry = try self.abi.findEntry(method, arg_types);

        if (entry == null) {
            return error.NoMatchingMethod;
        }

        return self.callEntry(entry.?, args, opts);
    }

    /// Calls a method on the contract identified by the supplied ABI entry.
    /// The caller can use `findEntry` or `findFirstEntry` and pass the result to this method to avoid the lookup each time.
    pub fn callEntry(self: *const Self, entry: *web3.abi.AbiEntry, args: anytype, opts: CallOptions) !ReturnValues {
        var encoder = web3.abi.CalldataArgEncoder.init(self.allocator);
        defer encoder.deinit();

        if (entry.inputs) |inputs| {
            inline for (inputs, args) |*input, arg| {
                try encoder.append(input.type, arg);
            }
        }

        return self.callInternal(entry, opts, encoder);
    }

    fn callInternal(self: *const Self, entry: *web3.abi.AbiEntry, opts: CallOptions, encoder: web3.abi.CalldataArgEncoder) !ReturnValues {
        std.debug.assert(entry.name != null);
        std.debug.assert(entry.type == .function);

        const arg_size = encoder.size();

        var calldata = try self.allocator.alloc(u8, 4 + arg_size);
        defer self.allocator.free(calldata);

        const selector = try entry.computeSelector();
        @memcpy(calldata[0..4], &selector);

        _ = try encoder.encodeBuf(calldata[4..]);

        var result = switch (opts.tx_type) {
            .eip1559 => |tx| try self.provider.call(web3.TransactionRequest{
                .from = opts.from,
                .to = self.address,
                .value = opts.value,
                .data = calldata[0 .. 4 + arg_size],
                .gas = opts.gas,
                .max_fee_per_gas = tx.max_fee_per_gas,
                .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
            }, opts.block_tag),
            .legacy => |tx| try self.provider.call(web3.TransactionRequest{
                .from = opts.from,
                .to = self.address,
                .value = opts.value,
                .data = calldata[0 .. 4 + arg_size],
                .gas = opts.gas,
                .gas_price = tx.gas_price,
            }, opts.block_tag),
        };

        return ReturnValues{
            .abi_entry = entry,
            .data = result,
        };
    }
};

/// A dynamically dispatched provider for performing functions required by the contract abstraction
pub const Provider = struct {
    const Self = @This();

    // The type erased pointer to the allocator implementation
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        call: *const fn (ctx: *anyopaque, tx: web3.TransactionRequest, block_tag: ?web3.BlockTag) anyerror![]const u8,
    };

    pub inline fn call(self: Self, tx: web3.TransactionRequest, block_tag: ?web3.BlockTag) ![]const u8 {
        return self.vtable.call(self.ptr, tx, block_tag);
    }
};
