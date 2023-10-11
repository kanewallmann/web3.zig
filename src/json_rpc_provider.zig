const std = @import("std");

const web3 = @import("web3.zig");

const parser_allocator = @import("parser_allocator.zig");

const INITIAL_RESPONSE_BUFFER_SIZE = 1024;
const MAX_RESPONSE_BUFFER_SIZE = 1024 * 1024;

fn JsonRpcResponse(comptime T: type) type {
    return struct {
        // id: u32,
        // jsonrpc: []const u8,
        result: T,
    };
}

const JsonRpcError = struct {
    // id: u32,
    // jsonrpc: []const u8,
    @"error": struct {
        code: i32,
        message: []const u8,
    },
};

const JsonFeeHistory = struct {
    oldest_block: u256,
    reward: ?[][]u256,
    base_fee_per_gas: []u256,
    gas_used_ratio: []f64,

    /// Free owned memory
    pub fn deinit(self: JsonFeeHistory, allocator: std.mem.Allocator) void {
        if (self.reward != null) {
            for (self.reward.?) |reward| {
                allocator.free(reward);
            }
            allocator.free(self.reward.?);
        }
        allocator.free(self.base_fee_per_gas);
        allocator.free(self.gas_used_ratio);
    }

    pub const json_def = .{
        .oldest_block = web3.json.JsonDef{
            .field_name = "oldestBlock",
        },
        .base_fee_per_gas = web3.json.JsonDef{
            .field_name = "baseFeePerGas",
        },
        .gas_used_ratio = web3.json.JsonDef{
            .field_name = "gasUsedRatio",
        },
    };
};

// Note: This struct must be identical to `web3.SyncStatus`
const JsonSyncStatus = union(enum) {
    not_syncing: void,
    syncing: web3.SyncData,

    pub fn fromJson(allocator: std.mem.Allocator, buffer: *[]const u8) !JsonSyncStatus {
        if (buffer.len >= "false".len and std.mem.eql(u8, buffer.*[0.."false".len], "false")) {
            buffer.* = buffer.*["false".len..];
            return JsonSyncStatus{ .not_syncing = void{} };
        } else {
            const data = try web3.json.JsonReader.parse(allocator, buffer, web3.SyncData);
            return JsonSyncStatus{
                .syncing = data,
            };
        }
    }
};

comptime {
    // Not a perfect comparison but can catch mistakes early
    std.debug.assert(@sizeOf(JsonSyncStatus) == @sizeOf(web3.SyncStatus));
    std.debug.assert(@typeInfo(JsonSyncStatus).Union.fields.len == @typeInfo(web3.SyncStatus).Union.fields.len);
}

const json_rpc_header =
    \\{"jsonrpc":"2.0","method":"
;
const params_header =
    \\,"params":
;
const id_header =
    \\","id":
;

/// Handles communication with an Ethereum JSON RPC server. Reference: https://ethereum.org/en/developers/docs/apis/json-rpc/
pub const JsonRpcProvider = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    endpoint: std.Uri,
    tag_buffer: [21]u8,
    last_error_code: isize = 0,
    last_error_message: ?[]const u8 = null,
    request_buffer: std.ArrayList(u8),
    response_buffer: std.ArrayList(u8),
    id: usize = 1,

    /// Initializes memory
    pub fn init(allocator: std.mem.Allocator, endpoint: std.Uri) !Self {
        return Self{
            .allocator = allocator,
            .tag_buffer = undefined,
            .request_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024),
            .response_buffer = try std.ArrayList(u8).initCapacity(allocator, INITIAL_RESPONSE_BUFFER_SIZE),
            .endpoint = endpoint,
        };
    }

    /// Frees owned memory
    pub fn deinit(self: *Self) void {
        self.request_buffer.clearAndFree();
        self.response_buffer.clearAndFree();
        if (self.last_error_message) |msg| {
            self.allocator.free(msg);
        }
    }

    /// Constructs a web3.Provider for use with the contract abstraction layer
    pub fn provider(self: *Self) web3.Provider {
        return .{
            .ptr = self,
            .vtable = &.{
                .call = providerCall,
                .estimateGas = providerEstimateGas,
                .send = providerSend,
                .sendRaw = providerSendRaw,
                .getTransactionCount = providerGetTransactionCount,
                .getFeeEstimate = providerGetFeeEstimate,
            },
        };
    }

    /// If a previous error exists, prints it to stderr
    pub fn printLastError(self: *Self) void {
        if (self.last_error_code == 0) {
            return;
        }
        const error_code = self.last_error_code;
        const error_msg = self.last_error_message.?;
        std.debug.print("RPC error ({}): {s}\n", .{ error_code, error_msg });
    }

    /// Implementation of `web3.Provider.call`
    fn providerCall(ctx: *anyopaque, allocator: std.mem.Allocator, tx: web3.TransactionRequest, block_tag: ?web3.BlockTag) ![]const u8 {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return @call(.always_inline, callAlloc, .{ self, allocator, tx, block_tag });
    }

    /// Implementation of `web3.Provider.estimateGas`
    fn providerEstimateGas(ctx: *anyopaque, tx: web3.TransactionRequest) !u256 {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return @call(.always_inline, estimateGas, .{ self, tx });
    }

    /// Implementation of `web3.Provider.send`
    fn providerSend(ctx: *anyopaque, tx: web3.TransactionRequest) !web3.Hash {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return @call(.always_inline, sendTransaction, .{ self, tx });
    }

    /// Implementation of `web3.Provider.sendRaw`
    fn providerSendRaw(ctx: *anyopaque, raw_tx: []const u8) !web3.Hash {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return @call(.always_inline, sendRawTransaction, .{ self, raw_tx });
    }

    /// Implementation of `web3.Provider.getTransactionCount`
    fn providerGetTransactionCount(ctx: *anyopaque, address: web3.Address, block_tag: ?web3.BlockTag) !u256 {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return @call(.always_inline, getTransactionCount, .{ self, address, block_tag });
    }

    /// Implementation of `web3.Provider.getFeeEstimate`
    fn providerGetFeeEstimate(ctx: *anyopaque, speed: web3.FeeEstimateSpeed) !web3.FeeEstimate {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return @call(.always_inline, getFeeEstimate, .{ self, speed });
    }

    /// web3_clientVersion
    pub fn getClientVersion(self: *Self) ![]const u8 {
        const params = web3.EmptyArray{};
        return self.send("web3_clientVersion", params, []const u8);
    }

    /// web3_sha3
    pub fn sha3(self: *Self, data: []const u8) ![]const u8 {
        const hex_data = web3.DataHexString{
            .raw = data,
        };
        const params = .{hex_data};
        const result_hex_data = try self.send("web3_sha3", params, web3.DataHexString);
        return result_hex_data.raw;
    }

    /// net_version
    pub fn getNetworkId(self: *Self) ![]const u8 {
        const params = web3.EmptyArray{};
        return self.send("net_version", params, []const u8);
    }

    /// net_listening
    pub fn getNetworkListening(self: *Self) !bool {
        const params = web3.EmptyArray{};
        return self.send("net_listening", params, bool);
    }

    /// net_peerCount
    pub fn getNetworkPeerCount(self: *Self) !u32 {
        const params = web3.EmptyArray{};
        return self.send("net_peerCount", params, u32);
    }

    /// eth_protocolVersion
    pub fn getProtocolVersion(self: *Self) ![]const u8 {
        const params = web3.EmptyArray{};
        return self.send("eth_protocolVersion", params, []const u8);
    }

    /// eth_syncing
    pub fn getSyncing(self: *Self) !web3.SyncStatus {
        const params = web3.EmptyArray{};
        const result = try self.send("eth_syncing", params, JsonSyncStatus);
        return @as(*const web3.SyncStatus, @ptrCast(&result)).*;
    }

    /// eth_coinbase
    pub fn getCoinbase(self: *Self) !web3.Address {
        const params = web3.EmptyArray{};
        return self.send("eth_coinbase", params, web3.Address);
    }

    /// eth_chainId
    pub fn getChainId(self: *Self) !u32 {
        const params = web3.EmptyArray{};
        return self.send("eth_chainId", params, u32);
    }

    /// eth_mining
    pub fn getMining(self: *Self) !bool {
        const params = web3.EmptyArray{};
        return self.send("eth_mining", params, bool);
    }

    /// eth_hashrate
    pub fn getHashrate(self: *Self) !u32 {
        const params = web3.EmptyArray{};
        return self.send("eth_hashrate", params, u32);
    }

    /// eth_gasPrice
    pub fn getGasPrice(self: *Self) !u256 {
        const params = web3.EmptyArray{};
        return self.send("eth_gasPrice", params, u256);
    }

    /// eth_accounts
    pub fn getAccounts(self: *Self) ![]web3.Address {
        const params = web3.EmptyArray{};
        return self.send("eth_accounts", params, []web3.Address);
    }

    /// eth_blockNumber
    pub fn getBlockNumber(self: *Self) !u64 {
        const params = web3.EmptyArray{};
        return self.send("eth_blockNumber", params, u64);
    }

    /// eth_getBalance
    pub fn getBalance(self: *Self, addr: web3.Address, block_tag: ?web3.BlockTag) !u256 {
        const params = .{ addr, self.blockTagToString(block_tag) };
        return self.send("eth_getBalance", params, u256);
    }

    /// eth_getStorageAt
    pub fn getStorageAt(self: *Self, addr: web3.Address, slot: u256, block_tag: ?web3.BlockTag) ![]const u8 {
        const params = .{ addr, slot, self.blockTagToString(block_tag) };
        const hex_data = try self.send("eth_getStorageAt", params, web3.DataHexString);
        return hex_data.raw;
    }

    /// eth_getTransactionCount
    pub fn getTransactionCount(self: *Self, addr: web3.Address, block_tag: ?web3.BlockTag) !u256 {
        const params = .{ addr, self.blockTagToString(block_tag) };
        return self.send("eth_getTransactionCount", params, u256);
    }

    /// eth_getBlockTransactionCountByHash
    pub fn getBlockTransactionCountByHash(self: *Self, block_hash: web3.Hash) !u32 {
        const params = .{block_hash};
        return self.send("eth_getBlockTransactionCountByHash", params, u32);
    }

    /// eth_getBlockTransactionCountByNumber
    pub fn getBlockTransactionCountByNumber(self: *Self, block_tag: ?web3.BlockTag) !u32 {
        const params = .{self.blockTagToString(block_tag)};
        return self.send("eth_getBlockTransactionCountByNumber", params, u32);
    }

    /// eth_getUncleCountByBlockHash
    pub fn getUncleCountByBlockHash(self: *Self, block_hash: web3.Hash) !u32 {
        const params = .{block_hash};
        return try self.send("eth_getUncleCountByBlockHash", params, u32);
    }

    /// eth_getUncleCountByBlockNumber
    pub fn getUncleCountByBlockNumber(self: *Self, block_tag: ?web3.BlockTag) !u32 {
        const params = .{self.blockTagToString(block_tag)};
        return try self.send("eth_getUncleCountByBlockNumber", params, u32);
    }

    /// eth_getCode
    pub fn getCode(self: *Self, addr: web3.Address, block_tag: ?web3.BlockTag) ![]const u8 {
        const params = .{ addr, self.blockTagToString(block_tag) };
        const hex_data = try self.send("eth_getCode", params, web3.DataHexString);
        return hex_data.raw;
    }

    /// eth_sign
    pub fn sign(self: *Self, addr: web3.Address, data: []const u8) ![]const u8 {
        const hex_data = web3.DataHexString{
            .raw = data,
        };
        const params = .{ addr, hex_data };
        const result_hex_data = try self.send("eth_sign", params, web3.DataHexString);
        return result_hex_data.raw;
    }

    /// eth_signTransaction
    pub fn signTransaction(self: *Self, tx: web3.TransactionRequest) ![]const u8 {
        var json_tx: *const web3.TransactionRequest = @ptrCast(&tx);
        const params = .{json_tx};
        var data: web3.DataHexString = try self.send("eth_signTransaction", params, web3.DataHexString);
        return data.raw;
    }

    /// eth_sendTransaction
    pub fn sendTransaction(self: *Self, tx: web3.TransactionRequest) !web3.Hash {
        var json_tx: *const web3.TransactionRequest = @ptrCast(&tx);
        const params = .{json_tx};
        return self.send("eth_sendTransaction", params, web3.Hash);
    }

    /// eth_sendRawTransaction
    pub fn sendRawTransaction(self: *Self, data: []const u8) !web3.Hash {
        const hex_data = web3.DataHexString{
            .raw = data,
        };
        const params = .{hex_data};
        return try self.send("eth_sendRawTransaction", params, web3.Hash);
    }

    /// eth_call
    pub inline fn call(self: *Self, tx: web3.TransactionRequest, block_tag: ?web3.BlockTag) ![]const u8 {
        return self.call(self.allocator, tx, block_tag);
    }

    pub fn callAlloc(self: *Self, allocator: std.mem.Allocator, tx: web3.TransactionRequest, block_tag: ?web3.BlockTag) ![]const u8 {
        var json_tx: *const web3.TransactionRequest = @ptrCast(&tx);
        const params = .{ json_tx, self.blockTagToString(block_tag) };
        var data: web3.DataHexString = try self.sendAlloc(allocator, "eth_call", params, web3.DataHexString);
        return data.raw;
    }

    /// eth_estimateGas
    pub fn estimateGas(self: *Self, tx: web3.TransactionRequest) !u256 {
        var json_tx: *const web3.TransactionRequest = @ptrCast(&tx);
        const params = .{json_tx};
        return self.send("eth_estimateGas", params, u256);
    }

    /// eth_getBlockByHash
    pub fn getBlockByHash(self: *Self, block_hash: web3.Hash, comptime full_transactions: bool) !web3.Block(full_transactions) {
        var full = full_transactions;
        const params = .{ block_hash, full };
        return self.send("eth_getBlockByHash", params, web3.Block(full_transactions));
    }

    /// eth_getBlockByNumber
    pub fn getBlockByNumber(self: *Self, block_tag: ?web3.BlockTag, comptime full_transactions: bool) !web3.Block(full_transactions) {
        var full = full_transactions;
        const params = .{ self.blockTagToString(block_tag), full };
        return self.send("eth_getBlockByNumber", params, web3.Block(full_transactions));
    }

    /// eth_getTransactionByHash
    pub fn getTransactionByHash(self: *Self, tx_hash: web3.Hash) !web3.Transaction {
        const params = .{tx_hash};
        return self.send("eth_getTransactionByHash", params, web3.Transaction);
    }

    /// eth_getTransactionByBlockHashAndIndex
    pub fn getTransactionByBlockHashAndIndex(self: *Self, block_hash: web3.Hash, index: u32) !web3.Transaction {
        const params = .{ block_hash, index };
        return self.send("eth_getTransactionByBlockHashAndIndex", params, web3.Transaction);
    }

    /// eth_getTransactionByBlockNumberAndIndex
    pub fn getTransactionByBlockNumberAndIndex(self: *Self, block_tag: ?web3.BlockTag, index: u32) !web3.Transaction {
        const params = .{ self.blockTagToString(block_tag), index };
        return self.send("eth_getTransactionByBlockNumberAndIndex", params, web3.Transaction);
    }

    /// eth_getTransactionReceipt
    pub fn getTransactionReceipt(self: *Self, tx_hash: web3.Hash) !web3.TransactionReceipt {
        const params = .{tx_hash};
        return self.send("eth_getTransactionReceipt", params, web3.TransactionReceipt);
    }

    /// eth_getUncleByBlockHashAndIndex
    pub fn getUngleByBlockHashAndIndex(self: *Self, block_hash: web3.Hash, index: u32) !web3.Block(false) {
        const params = .{ block_hash, index };
        return self.send("eth_getUncleByBlockHashAndIndex", params, web3.Block(false));
    }

    /// eth_getUncleByBlockNumberAndIndex
    pub fn getUngleByBlockNumberAndIndex(self: *Self, block_tag: ?web3.BlockTag, index: u32) !web3.Block(false) {
        const params = .{ self.blockTagToString(block_tag), index };
        return self.send("eth_getUncleByBlockHashAndIndex", params, web3.Block(false));
    }

    /// eth_getLogs
    pub fn getLogs(self: *Self, from_block_tag: ?web3.BlockTag, to_block_tag: ?web3.BlockTag, address: ?web3.Address, topics: ?[]const web3.Hash) !web3.Logs {
        const params = .{.{
            .fromBlock = self.blockTagToString(from_block_tag),
            .toBlock = self.blockTagToString(to_block_tag),
            .address = address,
            .topics = topics,
        }};

        const result = try self.send("eth_getLogs", params, []web3.Log);
        return web3.Logs{
            .raw = result,
        };
    }

    /// eth_feeHistory
    pub fn getFeeHistory(self: *Self, block_count: u16, newest_block: ?web3.BlockTag, reward_percentiles: ?[]const f64) !JsonFeeHistory {
        const params = .{ block_count, self.blockTagToString(newest_block), reward_percentiles };
        return self.send("eth_feeHistory", params, JsonFeeHistory);
    }

    /// Estimates values for max_fee_per_gas and max_priority_fee_per_gas.
    /// Looks at the past 4 blocks and averages the reward paid by a percentile of transactions controlled by the given speed.
    pub fn getFeeEstimate(self: *Self, speed: web3.FeeEstimateSpeed) !web3.FeeEstimate {
        const percentile: f64 = switch (speed) {
            .low => 20,
            .average => 50,
            .high => 90,
        };

        const percentiles: [1]f64 = .{percentile};
        const fee_history = try self.getFeeHistory(4, .{ .tag = .pending }, &percentiles);
        defer fee_history.deinit(self.allocator);

        var accum: u256 = 0;

        for (fee_history.reward.?) |reward| {
            accum += reward[0];
        }

        const average: u256 = accum / fee_history.reward.?.len;

        return .{
            .max_fee_per_gas = fee_history.base_fee_per_gas[fee_history.base_fee_per_gas.len - 1] + average,
            .max_priority_fee_per_gas = average,
        };
    }

    /// Makes an RPC call to the server and then attempts to decode the result into the given
    /// type. On failure, attempts to read an error message from the response and puts it in
    /// last_error_code and last_error_message. Memory is correctly cleaned up on error condition.
    /// Caller owns the memory otherwise.
    pub inline fn send(self: *Self, method: []const u8, args: anytype, comptime T: type) !T {
        return self.sendAlloc(self.allocator, method, args, T);
    }

    /// Same as `send` but with the supplied allocator instead of internal one
    pub fn sendAlloc(self: *Self, allocator: std.mem.Allocator, method: []const u8, args: anytype, comptime T: type) !T {
        try self.sendInternal(method, args);

        var arena = parser_allocator.ArenaAllocator.init(allocator);
        var parent_allocator = arena.allocator();

        var ptr = self.response_buffer.items;

        const success_result = web3.json.JsonReader.parse(parent_allocator, &ptr, JsonRpcResponse(T)) catch {
            arena.deinit();

            // Reset pointer and attempt to read an error instead
            ptr = self.response_buffer.items;
            const error_result = web3.json.JsonReader.parse(parent_allocator, &ptr, JsonRpcError) catch {
                arena.deinit();
                return error.InvalidResponse;
            };

            if (self.last_error_message) |msg| {
                allocator.free(msg);
            }

            self.last_error_message = error_result.@"error".message;
            self.last_error_code = error_result.@"error".code;

            arena.freeList();
            return error.RpcError;
        };

        arena.freeList();
        return success_result.result;
    }

    inline fn sendInternal(self: *Self, method: []const u8, args: anytype) !void {
        try self.constructRpcCall(self.id, method, args);
        self.id += 1;
        try self.performRequest(self.request_buffer.items);
    }

    fn constructRpcCall(self: *Self, id: usize, method: []const u8, params: anytype) !void {
        self.request_buffer.items.len = 0;
        var writer = self.request_buffer.writer();

        _ = try writer.write(json_rpc_header);
        _ = try writer.write(method);
        _ = try writer.write(id_header);
        _ = try std.fmt.formatInt(id, 10, .lower, .{}, writer);
        _ = try writer.write(params_header);
        _ = try web3.json.JsonWriter.write(params, writer);
        try writer.writeByte('}');
    }

    // TODO: Refactor this out to a "transport" interface and support WebSocket and IPC
    fn performRequest(self: *Self, data: []const u8) !void {
        var client = std.http.Client{
            .allocator = self.allocator,
        };
        defer client.deinit();

        var headers = std.http.Headers{ .allocator = self.allocator };
        defer headers.deinit();

        // Add content length header
        var length_str: [32]u8 = undefined;
        const length_str_len = std.fmt.formatIntBuf(length_str[0..], data.len, 10, .lower, .{});
        try headers.append("content-length", length_str[0..length_str_len]);

        try headers.append("content-type", "application/json");

        // Perform the request
        var req = try client.request(.POST, self.endpoint, headers, .{});
        defer req.deinit();

        try req.start();
        _ = try req.write(data);
        try req.wait();

        // Read entire result into buffer
        self.response_buffer.items.len = 0;
        try req.reader().readAllArrayList(&self.response_buffer, MAX_RESPONSE_BUFFER_SIZE);
    }

    /// Stringifies given block tag, uses internal buffer
    fn blockTagToString(self: *Self, block_tag: ?web3.BlockTag) web3.String {
        if (block_tag == null) {
            return web3.String.wrap("latest");
        }
        switch (block_tag.?) {
            .tag => |tag| {
                switch (tag) {
                    .earliest => return web3.String.wrap("earliest"),
                    .latest => return web3.String.wrap("latest"),
                    .safe => return web3.String.wrap("safe"),
                    .finalized => return web3.String.wrap("finalized"),
                    .pending => return web3.String.wrap("pending"),
                }
            },
            .number => |number| {
                self.tag_buffer[0] = '0';
                self.tag_buffer[1] = 'x';
                const len = std.fmt.formatIntBuf(self.tag_buffer[2..], number, 16, .lower, .{});
                return web3.String.wrap(self.tag_buffer[0 .. len + 2]);
            },
        }
    }
};
