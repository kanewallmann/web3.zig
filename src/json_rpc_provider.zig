const std = @import("std");

const web3 = @import("web3.zig");

const parser_allocator = @import("parser_allocator.zig");

const INITIAL_RESPONSE_BUFFER_SIZE = 1024;
const MAX_RESPONSE_BUFFER_SIZE = 1024 * 1024;

var latest = web3.String.wrap("latest");

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

// The following structs are identical versions of the corresponding library type but these
// structs us the naming convention of the API (i.e. camelCase) so that the parser, which
// uses comptime reflection, can parse them correctly

// Note: This struct must be identical to `web3.TransactionRequest`
const JsonTransactionRequest = struct {
    from: web3.Address,
    to: ?web3.Address = null,
    gas: ?u256 = null,
    gasPrice: ?u256 = null,
    maxPriorityFeePerGas: ?u256 = null,
    maxFeePerGas: ?u256 = null,
    value: ?u256 = null,
    data: ?[]const u8 = null,
};

// Note: This struct must be identical to `web3.Transaction`
const JsonTransaction = struct {
    blockHash: ?web3.Hash,
    blockNumber: ?u64,
    from: web3.Address,
    gas: u256,
    gasPrice: ?u256 = null,
    maxPriorityFeePerGas: ?u256 = null,
    maxFeePerGas: ?u256 = null,
    hash: web3.Hash,
    input: []const u8,
    to: web3.Address,
    transactionIndex: u32,
    value: u256,
    v: u8,
    r: u256,
    s: u256,
};

// Note: This struct must be identical to `web3.Log`
const JsonLog = struct {
    removed: bool,
    logIndex: ?u32,
    transactionIndex: ?u32,
    transactionHash: ?web3.Hash,
    blockHash: ?web3.Hash,
    blockNumber: ?u64,
    address: web3.Address,
    data: web3.DataHexString,
    topics: []web3.Hash,
};

// Note: This struct must be identical to `web3.Logs`
const JsonLogs = struct {
    raw: []JsonLog,

    pub fn fromJson(allocator: std.mem.Allocator, buffer: *[]const u8) !JsonLogs {
        return JsonLogs{
            .raw = try web3.json.JsonReader.parse(allocator, buffer, []JsonLog),
        };
    }
};

// Note: This struct must be identical to `web3.TransactionReceipt`
const JsonTransactionReceipt = struct {
    transactionHash: web3.Hash,
    transactionIndex: u32,
    blockHash: web3.Hash,
    blockNumber: u64,
    from: web3.Address,
    to: web3.Address,
    cumulativeGasUsed: u256,
    effectiveGasPrice: u256,
    gasUsed: u256,
    contractAddress: ?web3.Address,
    logs: []JsonLog,
    logsBloom: web3.FixedDataHexString(256),
    type: u8,
    status: u8,
};

// Note: This struct must be identical to `web3.Block`
fn JsonBlock(comptime full_transactions: bool) type {
    const TransactionType = if (full_transactions) JsonTransaction else web3.Hash;

    return struct {
        const Self = @This();

        difficulty: u256,
        extraData: web3.DataHexString,
        gasLimit: u256,
        gasUsed: u256,
        hash: ?web3.Hash,
        logsBloom: web3.FixedDataHexString(256),
        miner: web3.Address,
        mixHash: web3.Hash,
        nonce: ?web3.FixedDataHexString(8),
        number: ?u64,
        parentHash: web3.Hash,
        receiptsRoot: web3.Hash,
        sha3Uncles: web3.Hash,
        size: u64,
        stateRoot: web3.Hash,
        timestamp: u64,
        totalDifficulty: u256,
        transactionsRoot: web3.Hash,
        withdrawalsRoot: web3.Hash,
        transactions: []TransactionType,
        uncles: []web3.Hash,
        withdrawals: []struct {
            index: u64,
            validatorIndex: u64,
            address: web3.Address,
            amount: u64,
        },
    };
}

// Note: This struct must be identical to `web3.SyncData`
const JsonSyncData = struct {
    startingBlock: ?u64 = null,
    currentBlock: ?u64 = null,
    highestBlock: ?u64 = null,
};

// Note: This struct must be identical to `web3.SyncStatus`
const JsonSyncStatus = union(enum) {
    not_syncing: void,
    syncing: JsonSyncData,

    pub fn fromJson(allocator: std.mem.Allocator, buffer: *[]const u8) !JsonSyncStatus {
        if (buffer.len >= "false".len and std.mem.eql(u8, buffer.*[0.."false".len], "false")) {
            buffer.* = buffer.*["false".len..];
            return JsonSyncStatus{ .not_syncing = void{} };
        } else {
            const data = try web3.json.JsonReader.parse(allocator, buffer, JsonSyncData);
            return JsonSyncStatus{
                .syncing = data,
            };
        }
    }
};

comptime {
    // Not a perfect comparison but can catch mistakes early
    std.debug.assert(@sizeOf(JsonTransactionRequest) == @sizeOf(web3.TransactionRequest));
    std.debug.assert(@typeInfo(JsonTransactionRequest).Struct.fields.len == @typeInfo(web3.TransactionRequest).Struct.fields.len);
    std.debug.assert(@sizeOf(JsonTransaction) == @sizeOf(web3.Transaction));
    std.debug.assert(@typeInfo(JsonTransaction).Struct.fields.len == @typeInfo(web3.Transaction).Struct.fields.len);
    std.debug.assert(@sizeOf(JsonLog) == @sizeOf(web3.Log));
    std.debug.assert(@typeInfo(JsonLog).Struct.fields.len == @typeInfo(web3.Log).Struct.fields.len);
    std.debug.assert(@sizeOf(JsonLogs) == @sizeOf(web3.Logs));
    std.debug.assert(@typeInfo(JsonLogs).Struct.fields.len == @typeInfo(web3.Logs).Struct.fields.len);
    std.debug.assert(@sizeOf(JsonTransactionReceipt) == @sizeOf(web3.TransactionReceipt));
    std.debug.assert(@typeInfo(JsonTransactionReceipt).Struct.fields.len == @typeInfo(web3.TransactionReceipt).Struct.fields.len);
    std.debug.assert(@sizeOf(JsonSyncData) == @sizeOf(web3.SyncData));
    std.debug.assert(@typeInfo(JsonSyncData).Struct.fields.len == @typeInfo(web3.SyncData).Struct.fields.len);
    std.debug.assert(@sizeOf(JsonSyncStatus) == @sizeOf(web3.SyncStatus));
    std.debug.assert(@typeInfo(JsonSyncStatus).Union.fields.len == @typeInfo(web3.SyncStatus).Union.fields.len);
    std.debug.assert(@sizeOf(JsonBlock(true)) == @sizeOf(web3.Block(true)));
    std.debug.assert(@typeInfo(JsonBlock(true)).Struct.fields.len == @typeInfo(web3.Block(true)).Struct.fields.len);
    std.debug.assert(@sizeOf(JsonBlock(false)) == @sizeOf(web3.Block(false)));
    std.debug.assert(@typeInfo(JsonBlock(false)).Struct.fields.len == @typeInfo(web3.Block(false)).Struct.fields.len);
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
    fn providerCall(ctx: *anyopaque, tx: web3.TransactionRequest, block_tag: ?web3.BlockTag) ![]const u8 {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return @call(.always_inline, call, .{ self, tx, block_tag });
    }

    /// web3_clientVersion
    pub fn getClientVersion(self: *Self) ![]const u8 {
        var params = web3.EmptyArray{};
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
        var params = web3.EmptyArray{};
        return self.send("net_version", params, []const u8);
    }

    /// net_listening
    pub fn getNetworkListening(self: *Self) !bool {
        var params = web3.EmptyArray{};
        return self.send("net_listening", params, bool);
    }

    /// net_peerCount
    pub fn getNetworkPeerCount(self: *Self) !u32 {
        var params = web3.EmptyArray{};
        return self.send("net_peerCount", params, u32);
    }

    /// eth_protocolVersion
    pub fn getProtocolVersion(self: *Self) ![]const u8 {
        var params = web3.EmptyArray{};
        return self.send("eth_protocolVersion", params, []const u8);
    }

    /// eth_syncing
    pub fn getSyncing(self: *Self) !web3.SyncStatus {
        var params = web3.EmptyArray{};
        const result = try self.send("eth_syncing", params, JsonSyncStatus);
        return @as(*const web3.SyncStatus, @ptrCast(&result)).*;
    }

    /// eth_coinbase
    pub fn getCoinbase(self: *Self) !web3.Address {
        var params = web3.EmptyArray{};
        return self.send("eth_coinbase", params, web3.Address);
    }

    /// eth_chainId
    pub fn getChainId(self: *Self) !u32 {
        var params = web3.EmptyArray{};
        const hex_data = try self.send("eth_chainId", params, web3.IntHexString(u32));
        return hex_data.raw;
    }

    /// eth_mining
    pub fn getMining(self: *Self) !bool {
        var params = web3.EmptyArray{};
        return self.send("eth_mining", params, bool);
    }

    /// eth_hashrate
    pub fn getHashrate(self: *Self) !u32 {
        var params = web3.EmptyArray{};
        const hex_data = try self.send("eth_hashrate", params, web3.IntHexString(u32));
        return hex_data.raw;
    }

    /// eth_gasPrice
    pub fn getGasPrice(self: *Self) !u256 {
        var params = web3.EmptyArray{};
        const hex_data = try self.send("eth_gasPrice", params, web3.IntHexString(u256));
        return hex_data.raw;
    }

    /// eth_accounts
    pub fn getAccounts(self: *Self) ![]web3.Address {
        var params = web3.EmptyArray{};
        return self.send("eth_accounts", params, []web3.Address);
    }

    /// eth_blockNumber
    pub fn getBlockNumber(self: *Self) !u64 {
        var params = web3.EmptyArray{};
        return self.send("eth_blockNumber", params, u64);
    }

    /// eth_getBalance
    pub fn getBalance(self: *Self, addr: web3.Address, block_tag: ?web3.BlockTag) !u256 {
        var params = .{ addr, self.blockTagToString(block_tag) };
        return self.send("eth_getBalance", params, u256);
    }

    /// eth_getStorageAt
    pub fn getStorageAt(self: *Self, addr: web3.Address, slot: u256, block_tag: ?web3.BlockTag) ![]const u8 {
        const hex_slot = web3.IntHexString(u256){
            .raw = slot,
        };
        var params = .{ addr, hex_slot, self.blockTagToString(block_tag) };
        const hex_data = try self.send("eth_getStorageAt", params, web3.DataHexString);
        return hex_data.raw;
    }

    /// eth_getTransactionCount
    pub fn getTransactionCount(self: *Self, addr: web3.Address, block_tag: ?web3.BlockTag) !u256 {
        var params = .{ addr, self.blockTagToString(block_tag) };
        return self.send("eth_getTransactionCount", params, u256);
    }

    /// eth_getBlockTransactionCountByHash
    pub fn getBlockTransactionCountByHash(self: *Self, block_hash: web3.Hash) !u32 {
        var params = .{block_hash};
        const hex_data = try self.send("eth_getBlockTransactionCountByHash", params, web3.IntHexString(u32));
        return hex_data.raw;
    }

    /// eth_getBlockTransactionCountByNumber
    pub fn getBlockTransactionCountByNumber(self: *Self, block_tag: ?web3.BlockTag) !u32 {
        var params = .{self.blockTagToString(block_tag)};
        const hex_data = try self.send("eth_getBlockTransactionCountByNumber", params, web3.IntHexString(u32));
        return hex_data.raw;
    }

    /// eth_getUncleCountByBlockHash
    pub fn getUncleCountByBlockHash(self: *Self, block_hash: web3.Hash) !u32 {
        var params = .{block_hash};
        const hex_data = try self.send("eth_getUncleCountByBlockHash", params, web3.IntHexString(u32));
        return hex_data.raw;
    }

    /// eth_getUncleCountByBlockNumber
    pub fn getUncleCountByBlockNumber(self: *Self, block_tag: ?web3.BlockTag) !u32 {
        var params = .{self.blockTagToString(block_tag)};
        const hex_data = try self.send("eth_getUncleCountByBlockNumber", params, web3.IntHexString(u32));
        return hex_data.raw;
    }

    /// eth_getCode
    pub fn getCode(self: *Self, addr: web3.Address, block_tag: ?web3.BlockTag) ![]const u8 {
        var params = .{ addr, self.blockTagToString(block_tag) };
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
        var json_tx: *const JsonTransactionRequest = @ptrCast(&tx);
        var params = .{json_tx};
        var data: web3.DataHexString = try self.send("eth_signTransaction", params, web3.DataHexString);
        return data.raw;
    }

    /// eth_sendTransaction
    pub fn sendTransaction(self: *Self, tx: web3.TransactionRequest) ![]const u8 {
        var json_tx: *const JsonTransactionRequest = @ptrCast(&tx);
        var params = .{json_tx};
        var data: web3.DataHexString = try self.send("eth_sendTransaction", params, web3.DataHexString);
        return data.raw;
    }

    /// eth_sendRawTransactkon
    pub fn sendRawTransaction(self: *Self, data: []const u8) ![]const u8 {
        const hex_data = web3.DataHexString{
            .raw = data,
        };
        const params = .{hex_data};
        const result_hex_data = try self.send("eth_sendRawTransaction", params, web3.DataHexString);
        return result_hex_data.raw;
    }

    /// eth_call
    pub fn call(self: *Self, tx: web3.TransactionRequest, block_tag: ?web3.BlockTag) ![]const u8 {
        var json_tx: *const JsonTransactionRequest = @ptrCast(&tx);
        var params = .{ json_tx, self.blockTagToString(block_tag) };
        var data: web3.DataHexString = try self.send("eth_call", params, web3.DataHexString);
        return data.raw;
    }

    /// eth_estimateGas
    pub fn estimateGas(self: *Self, tx: web3.TransactionRequest) !u256 {
        var json_tx: *const JsonTransactionRequest = @ptrCast(&tx);
        var params = .{json_tx};
        const hex_data = try self.send("eth_estimateGas", params, web3.IntHexString(u256));
        return hex_data.raw;
    }

    /// eth_getBlockByHash
    pub fn getBlockByHash(self: *Self, block_hash: web3.Hash, comptime full_transactions: bool) !web3.Block(full_transactions) {
        var full = full_transactions;
        var params = .{ block_hash, full };
        const result = try self.send("eth_getBlockByHash", params, JsonBlock(full_transactions));
        return @as(*const web3.Block(full), @ptrCast(&result)).*;
    }

    /// eth_getBlockByNumber
    pub fn getBlockByNumber(self: *Self, block_tag: ?web3.BlockTag, comptime full_transactions: bool) !web3.Block(full_transactions) {
        var full = full_transactions;
        var params = .{ self.blockTagToString(block_tag), full };
        const result = try self.send("eth_getBlockByNumber", params, JsonBlock(full_transactions));
        return @as(*const web3.Block(full_transactions), @ptrCast(&result)).*;
    }

    /// eth_getTransactionByHash
    pub fn getTransactionByHash(self: *Self, tx_hash: web3.Hash) !web3.Transaction {
        var params = .{tx_hash};
        const result = try self.send("eth_getTransactionByHash", params, JsonTransaction);
        return @as(*const web3.Transaction, @ptrCast(&result)).*;
    }

    /// eth_getTransactionByBlockHashAndIndex
    pub fn getTransactionByBlockHashAndIndex(self: *Self, block_hash: web3.Hash, index: u32) !web3.Transaction {
        var params = .{ block_hash, web3.IntHexString(u32).wrap(index) };
        const result = try self.send("eth_getTransactionByBlockHashAndIndex", params, JsonTransaction);
        return @as(*const web3.Transaction, @ptrCast(&result)).*;
    }

    /// eth_getTransactionByBlockNumberAndIndex
    pub fn getTransactionByBlockNumberAndIndex(self: *Self, block_tag: ?web3.BlockTag, index: u32) !web3.Transaction {
        var params = .{ self.blockTagToString(block_tag), web3.IntHexString(u32).wrap(index) };
        const result = try self.send("eth_getTransactionByBlockNumberAndIndex", params, JsonTransaction);
        return @as(*const web3.Transaction, @ptrCast(&result)).*;
    }

    /// eth_getTransactionReceipt
    pub fn getTransactionReceipt(self: *Self, tx_hash: web3.Hash) !web3.TransactionReceipt {
        var params = .{tx_hash};
        const result = try self.send("eth_getTransactionReceipt", params, JsonTransactionReceipt);
        return @as(*const web3.TransactionReceipt, @ptrCast(&result)).*;
    }

    /// eth_getUncleByBlockHashAndIndex
    pub fn getUngleByBlockHashAndIndex(self: *Self, block_hash: web3.Hash, index: u32) !web3.Block(false) {
        var params = .{ block_hash, web3.IntHexString(u32).wrap(index) };
        const result = try self.send("eth_getUncleByBlockHashAndIndex", params, JsonBlock(false));
        return @as(*const web3.Block(false), @ptrCast(&result)).*;
    }

    /// eth_getUncleByBlockNumberAndIndex
    pub fn getUngleByBlockNumberAndIndex(self: *Self, block_tag: ?web3.BlockTag, index: u32) !web3.Block(false) {
        var params = .{ self.blockTagToString(block_tag), web3.IntHexString(u32).wrap(index) };
        const result = try self.send("eth_getUncleByBlockHashAndIndex", params, JsonBlock(false));
        return @as(*const web3.Block(false), @ptrCast(&result)).*;
    }

    /// eth_getLogs
    pub fn getLogs(self: *Self, from_block_tag: ?web3.BlockTag, to_block_tag: ?web3.BlockTag, address: ?web3.Address, topics: ?[]const web3.Hash) !web3.Logs {
        var params = .{.{
            .fromBlock = self.blockTagToString(from_block_tag),
            .toBlock = self.blockTagToString(to_block_tag),
            .address = address,
            .topics = topics,
        }};

        const result = try self.send("eth_getLogs", params, JsonLogs);
        return @as(*const web3.Logs, @ptrCast(&result)).*;
    }

    /// Makes an RPC call to the server and then attempts to decode the result into the given
    /// type. On failure, attempts to read an error message from the response and puts it in
    /// last_error_code and last_error_message. Memory is correctly cleaned up on error condition.
    /// Caller owns the memory otherwise.
    pub fn send(self: *Self, method: []const u8, args: anytype, comptime T: type) !T {
        try self.sendInternal(method, args);

        var arena = parser_allocator.ArenaAllocator.init(self.allocator);
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
                self.allocator.free(msg);
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
                const len = std.fmt.formatIntBuf(&self.tag_buffer, number, 10, .lower, .{});
                return web3.String.wrap(self.tag_buffer[0..len]);
            },
        }
    }
};
