const std = @import("std");
const web3 = @import("web3.zig");

// TODO: This should accept an array of private keys and a count for hd wallet and pick the correct signer based on tx.from field
/// Handles the local signing of transactions. Can be created directly with a private key
/// or can derive a private key from a given bip-39 mnemonic.
pub const LocalSigner = struct {
    const Self = @This();

    pub const Options = struct {
        chain_id: u256 = 1,
    };

    pub const HdOptions = struct {
        chain_id: u256 = 1,
        path: []const u8 = "m/44'/60'/0'/0",
        index: u32 = 0,
    };

    allocator: std.mem.Allocator,
    chain_id: u256 = 1,
    signing_key: web3.ecdsa.SigningKey,
    address: web3.Address,

    /// Creates a signer from the given private key
    pub fn fromPrivateKey(allocator: std.mem.Allocator, private_key: [32]u8, options: Options) !Self {
        const key = web3.ecdsa.SigningKey.wrap(private_key);
        return Self{
            .allocator = allocator,
            .chain_id = options.chain_id,
            .signing_key = key,
            .address = try key.toAddress(),
        };
    }

    /// Creates a signer from the given hex encoded private key
    pub fn fromString(allocator: std.mem.Allocator, private_key_: []const u8, options: Options) !Self {
        var private_key = private_key_;

        if (private_key.len == 66 and std.mem.eql(u8, private_key[0..2], "0x")) {
            private_key = private_key[2..];
        }

        if (private_key.len != 64) {
            return error.UnexpectedLength;
        }

        var raw: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&raw, private_key);
        return fromPrivateKey(allocator, raw, options);
    }

    /// Creates this type from a bip-39 mnemonic phrase
    pub fn fromMnemonic(allocator: std.mem.Allocator, mnemonic: []const u8, options: HdOptions) !Self {
        const seed = try web3.mnemonic.seedFromMnemonic(mnemonic);
        const account_node = try web3.hdwallet.Node.fromSeedAndPath(&seed, options.path);
        const node = try account_node.derive(options.index);

        const raw = try node.getPrivateKey();
        return fromPrivateKey(allocator, raw, .{
            .chain_id = options.chain_id,
        });
    }

    /// Returns a Signer interface for use with SingingProvider
    pub fn signer(self: *Self) Signer {
        return .{
            .ptr = self,
            .vtable = &.{
                .signTransaction = signerSignTransaction,
                .getAddress = signerGetAddress,
            },
        };
    }

    // Implementation of `web3.Signer.signTransaction`
    fn signerSignTransaction(ctx: *anyopaque, allocator: std.mem.Allocator, tx: web3.TransactionRequest) ![]const u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));
        const signed_tx = try @call(.always_inline, signTransaction, .{ self, tx });
        return signed_tx.encode(allocator);
    }

    /// Takes an unsigned TransactionRequest and returns a signed one.
    /// Errors if the request has an invalid from field.
    /// Errors if the request chain_id does not match the signer's chain_id.
    pub fn signTransaction(self: *const Self, tx_: web3.TransactionRequest) !web3.TransactionRequest {
        var tx = tx_;

        if (tx.chain_id == null) {
            tx.chain_id = self.chain_id;
        } else if (tx.chain_id != self.chain_id) {
            return error.InvalidChainId;
        }

        const raw_tx = try tx.encode(self.allocator);
        defer self.allocator.free(raw_tx);

        var signature = try self.signing_key.sign(raw_tx);
        signature.addChainId(self.chain_id) catch unreachable;

        tx.addSignature(signature);

        return tx;
    }

    // Implementation of `web3.Signer.getAddress`
    fn signerGetAddress(ctx: *anyopaque) !web3.Address {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.address;
    }

    pub fn getAddress(self: Self) !web3.Address {
        return self.address;
    }

    pub fn sign(self: Self, message: []const u8) !web3.ecdsa.Signature {
        return self.signing_key.sign(message);
    }
};

/// A dynamically dispatched signer for signing Ethereum transactions
pub const Signer = struct {
    const Self = @This();

    // The type erased pointer to the implementation
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        signTransaction: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, tx: web3.TransactionRequest) anyerror![]const u8,
        getAddress: *const fn (ctx: *anyopaque) anyerror!web3.Address,
    };

    pub inline fn signTransaction(self: Self, allocator: std.mem.Allocator, tx: web3.TransactionRequest) ![]const u8 {
        return self.vtable.signTransaction(self.ptr, allocator, tx);
    }

    pub inline fn getAddress(self: Self) !web3.Address {
        return self.vtable.getAddress(self.ptr);
    }
};

/// A wrapper around a Provider that delegates signing to a Signer which handles signing transaction requests
/// and also sets the empty fields on TransactionRequests based on the signer
pub const SigningProvider = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    signer: Signer,
    child_provider: web3.Provider,

    pub fn init(allocator: std.mem.Allocator, signer: Signer, child_provider: web3.Provider) Self {
        return Self{
            .allocator = allocator,
            .signer = signer,
            .child_provider = child_provider,
        };
    }

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

    /// Attempts to fill in missing values of a TransactionRequest.
    /// Fills from with signer address.
    /// Fills nonce with pending transaction count of signer.
    /// Fills gas with estimated gas via call to child_provider.
    /// Fills fee parameters with estimates based on current network conditions.
    /// Errors if from is not empty and set to an unknown address.
    pub fn populateTransaction(self: *Self, tx_: web3.TransactionRequest, speed: web3.FeeEstimateSpeed) !web3.TransactionRequest {
        var tx = tx_;

        const addr = try self.signer.getAddress();

        // Fill from
        if (tx.from == null) {
            tx.from = addr;
        } else {
            if (!std.mem.eql(u8, &tx.from.?.raw, &addr.raw)) {
                return error.InvalidFrom;
            }
        }

        // Fill nonce
        if (tx.nonce == null) {
            const tx_count = try self.child_provider.getTransactionCount(addr, .{ .tag = .pending });
            tx.nonce = tx_count;
        }

        // Fill gas limit
        if (tx.gas == null) {
            tx.gas = try self.child_provider.estimateGas(tx);
        }

        // Fill fees
        if (tx.gas_price == null and (tx.max_fee_per_gas == null or tx.max_priority_fee_per_gas == null)) {
            const estimate = try self.child_provider.getFeeEstimate(speed);

            if (tx.max_fee_per_gas == null) {
                tx.max_fee_per_gas = estimate.max_fee_per_gas;
            }

            if (tx.max_priority_fee_per_gas == null) {
                tx.max_priority_fee_per_gas = estimate.max_priority_fee_per_gas;
            }

            if (tx.max_priority_fee_per_gas.? > tx.max_fee_per_gas.?) {
                return error.PriorityFeeExceedsMaxFee;
            }
        }

        return tx;
    }

    /// Implementation of `web3.Provider.send`
    fn providerSend(ctx: *anyopaque, tx_: web3.TransactionRequest) !web3.Hash {
        var self: *Self = @ptrCast(@alignCast(ctx));

        const tx = try self.populateTransaction(tx_, .average);
        const signed_tx = try self.signer.signTransaction(self.allocator, tx);
        defer self.allocator.free(signed_tx);

        return self.child_provider.sendRaw(signed_tx);
    }

    /// Implementation of `web3.Provider.call`
    fn providerCall(ctx: *anyopaque, allocator: std.mem.Allocator, tx_: web3.TransactionRequest, block_tag: ?web3.BlockTag) ![]const u8 {
        var self: *Self = @ptrCast(@alignCast(ctx));

        var tx = tx_;

        if (tx.from == null) {
            tx.from = try self.signer.getAddress();
        }

        return self.child_provider.call(allocator, tx, block_tag);
    }

    /// Implementation of `web3.Provider.estimateGas`
    fn providerEstimateGas(ctx: *anyopaque, tx_: web3.TransactionRequest) !u256 {
        var self: *Self = @ptrCast(@alignCast(ctx));

        var tx = tx_;

        if (tx.from == null) {
            tx.from = try self.signer.getAddress();
        }

        return self.child_provider.estimateGas(tx);
    }

    /// Implementation of `web3.Provider.sendRaw`
    fn providerSendRaw(ctx: *anyopaque, raw_tx: []const u8) !web3.Hash {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return self.child_provider.sendRaw(raw_tx);
    }

    /// Implementation of `web3.Provider.getTransactionCount`
    fn providerGetTransactionCount(ctx: *anyopaque, address: web3.Address, block_tag: ?web3.BlockTag) !u256 {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return self.child_provider.getTransactionCount(address, block_tag);
    }

    /// Implementation of `web3.Provider.getFeeEstimate`
    fn providerGetFeeEstimate(ctx: *anyopaque, speed: web3.FeeEstimateSpeed) !web3.FeeEstimate {
        var self: *Self = @ptrCast(@alignCast(ctx));
        return self.child_provider.getFeeEstimate(speed);
    }
};

// test "sign transaction" {
//     const allocator = std.testing.allocator;

//     const mnemonic = "rose update response coin cream column wine timber lens repeat short trial mean pear conduct jealous ready negative mind army dance pulse noise capable";
//     const signer = try LocalSigner.fromMnemonic(allocator, mnemonic, .{});

//     const addr = try signer.getAddress();
//     std.debug.print("{}\n", .{addr});

//     const tx = try signer.signTransaction(.{
//         .to = web3.Address.zero,
//         .value = 10000,
//         .nonce = 500,
//         .max_fee_per_gas = 10000,
//         .max_priority_fee_per_gas = 10000,
//         .gas = 21000,
//     });

//     std.debug.print("{any}\n", .{tx});
// }
