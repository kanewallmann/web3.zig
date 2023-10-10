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

/// Abstraction around Ethereum contracts (currently being refactored)
pub const Contract = struct {
    const Self = @This();

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
    pub fn call(self: *const Self, method: []const u8, args: anytype, opts: web3.CallOptions) !ReturnValues {
        const entry = try self.abi.findFirstEntry(method);

        if (entry == null) {
            return error.NoMatchingMethod;
        }

        return self.callEntry(entry.?, args, opts);
    }

    /// Finds a method with matching name and args and calls it on the contract
    pub fn callOverloaded(self: *const Self, method: []const u8, arg_types: []const web3.AbiType, args: anytype, opts: web3.CallOptions) !ReturnValues {
        std.debug.assert(arg_types.len == args.len);
        const entry = try self.abi.findEntry(method, arg_types);

        if (entry == null) {
            return error.NoMatchingMethod;
        }

        return self.callEntry(entry.?, args, opts);
    }

    /// Calls a method on the contract identified by the supplied ABI entry.
    /// The caller can use `findEntry` or `findFirstEntry` and pass the result to this method to avoid the lookup each time.
    pub fn callEntry(self: *const Self, entry: *web3.abi.AbiEntry, args: anytype, opts: web3.CallOptions) !ReturnValues {
        std.debug.assert(entry.name != null);
        std.debug.assert(entry.type == .function);

        // const selector = try entry.computeSelector();
        const calldata = try web3.abi.CalldataArgEncoder.encodeWithSelector(self.allocator, entry.name, args);
        defer self.allocator.free(calldata);

        return ReturnValues{
            .abi_entry = entry,
            .data = try self.callInternal(calldata, opts),
        };
    }

    fn callInternal(self: *const Self, calldata: []const u8, opts: web3.CallOptions) ![]const u8 {
        return switch (opts.tx_type) {
            .eip1559 => |tx| try self.provider.call(web3.TransactionRequest{
                .from = opts.from,
                .to = self.address,
                .value = opts.value,
                .data = calldata,
                .gas = opts.gas,
                .max_fee_per_gas = tx.max_fee_per_gas,
                .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
            }, opts.block_tag),
            .legacy => |tx| try self.provider.call(web3.TransactionRequest{
                .from = opts.from,
                .to = self.address,
                .value = opts.value,
                .data = calldata,
                .gas = opts.gas,
                .gas_price = tx.gas_price,
            }, opts.block_tag),
        };
    }
};

pub const ContractCaller = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    address: web3.Address,
    provider: web3.Provider,

    /// Intializes a new contract
    pub fn init(allocator: std.mem.Allocator, address: web3.Address, provider: web3.Provider) Self {
        return Self{
            .allocator = allocator,
            .address = address,
            .provider = provider,
        };
    }

    /// Calls the supplied method on the contract with the given args.
    /// Tries to decode the result into a type T
    pub fn call(self: *const Self, method: []const u8, args: anytype, comptime T: type, opts: web3.CallOptions) !T {
        const selector = try web3.abi.computeSelector(method, @TypeOf(args));
        return self.callSelector(selector, args, T, opts);
    }

    pub fn callSelector(self: *const Self, selector: [4]u8, args: anytype, comptime T: type, opts: web3.CallOptions) !T {
        const calldata = try web3.abi.CalldataArgEncoder.encodeWithSelector(self.allocator, selector, args);
        defer self.allocator.free(calldata);
        const result = try self.callInternal(calldata, opts);
        defer self.allocator.free(result);
        return web3.abi.decodeArg(self.allocator, result, 0, T);
    }

    fn callInternal(self: *const Self, calldata: []const u8, opts: web3.CallOptions) ![]const u8 {
        return switch (opts.tx_type) {
            .eip1559 => |tx| try self.provider.call(web3.TransactionRequest{
                .from = opts.from,
                .to = self.address,
                .value = opts.value,
                .data = web3.DataHexString.wrap(calldata),
                .gas = opts.gas,
                .max_fee_per_gas = tx.max_fee_per_gas,
                .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
            }, opts.block_tag),
            .legacy => |tx| try self.provider.call(web3.TransactionRequest{
                .from = opts.from,
                .to = self.address,
                .value = opts.value,
                .data = web3.DataHexString.wrap(calldata),
                .gas = opts.gas,
                .gas_price = tx.gas_price,
            }, opts.block_tag),
        };
    }
};

/// A dynamically dispatched provider for performing functions required by the contract abstraction
pub const Provider = struct {
    const Self = @This();

    // The type erased pointer to the implementation
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        call: *const fn (ctx: *anyopaque, tx: web3.TransactionRequest, block_tag: ?web3.BlockTag) anyerror![]const u8,
        estimateGas: *const fn (ctx: *anyopaque, tx: web3.TransactionRequest) anyerror!u256,
        send: *const fn (ctx: *anyopaque, tx: web3.TransactionRequest) anyerror!web3.Hash,
        sendRaw: *const fn (ctx: *anyopaque, raw_tx: []const u8) anyerror!web3.Hash,
        getTransactionCount: *const fn (ctx: *anyopaque, address: web3.Address, block_tag: ?web3.BlockTag) anyerror!u256,
        getFeeEstimate: *const fn (ctx: *anyopaque, speed: web3.FeeEstimateSpeed) anyerror!web3.FeeEstimate,
    };

    pub inline fn call(self: Self, tx: web3.TransactionRequest, block_tag: ?web3.BlockTag) ![]const u8 {
        return self.vtable.call(self.ptr, tx, block_tag);
    }

    pub inline fn estimateGas(self: Self, tx: web3.TransactionRequest) !u256 {
        return self.vtable.estimateGas(self.ptr, tx);
    }

    pub inline fn send(self: Self, tx: web3.TransactionRequest) !web3.Hash {
        return self.vtable.send(self.ptr, tx);
    }

    pub inline fn sendRaw(self: Self, raw_tx: []const u8) !web3.Hash {
        return self.vtable.sendRaw(self.ptr, raw_tx);
    }

    pub inline fn getTransactionCount(self: Self, address: web3.Address, block_tag: ?web3.BlockTag) !u256 {
        return self.vtable.getTransactionCount(self.ptr, address, block_tag);
    }

    pub inline fn getFeeEstimate(self: Self, speed: web3.FeeEstimateSpeed) !web3.FeeEstimate {
        return self.vtable.getFeeEstimate(self.ptr, speed);
    }
};
