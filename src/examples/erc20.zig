const std = @import("std");

const web3 = @import("web3");

const addr = web3.Address.fromString("0xf977814e90da44bfa03b6295a0616a897441acec") catch unreachable; // Binance wallet
const usdt = web3.Address.fromString("0xdac17f958d2ee523a2206206994597c13d831ec7") catch unreachable;

/// Wrapping the contract abstraction in a struct can simplify making calls
const ERC20 = struct {
    const Self = @This();

    contract: web3.ContractCaller,

    pub fn init(allocator: std.mem.Allocator, address: web3.Address, provider: web3.Provider) ERC20 {
        return ERC20{
            .contract = web3.ContractCaller.init(allocator, address, provider),
        };
    }

    pub fn balanceOf(self: Self, address: web3.Address, opts: web3.CallOptions) !u256 {
        // The compiler will hash the signature and emit the 4 byte selector so it doesn't have to at run time
        const selector = comptime try web3.abi.computeSelectorFromSig("balanceOf(address)");
        return self.contract.callSelector(selector, .{address}, u256, opts);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.detectLeaks();
    const allocator = gpa.allocator();

    // Get rpc endpoint from first arg
    var args = try std.process.argsWithAllocator(allocator);
    _ = args.next(); // Skip exe name
    const rpc_endpoint = args.next() orelse @panic("Supply RPC endpoint as first argument");

    // Init a provider
    var json_rpc_provider = try web3.JsonRpcProvider.init(allocator, try std.Uri.parse(rpc_endpoint));
    defer json_rpc_provider.deinit();

    // Create an erc20 instance
    const erc20 = ERC20.init(allocator, usdt, json_rpc_provider.provider());

    // Call balanceOf(address)
    const usdt_balance = web3.FixedPoint(8, u256).wrap(try erc20.balanceOf(addr, .{}));

    // Get ETH balance (null here defaults to "latest")
    const eth_balance_wei = json_rpc_provider.getBalance(addr, null) catch |err| switch (err) {
        error.RpcError => {
            // The last RPC error details is stored in `last_error_code` and `last_error_message` of `JsonRpcProvider`
            json_rpc_provider.printLastError();
            return;
        },
        else => return err,
    };
    // Ether is a typedef of FixedPoint(18, u256) which is a utility for working with fixed point integers
    const eth_balance = web3.Ether.wrap(eth_balance_wei);

    // Get current block number
    const block_number = try json_rpc_provider.getBlockNumber();

    // Print results
    std.debug.print("\n{} has {:.6} USDT and {:.6} ETH at block {:}\n", .{ addr, usdt_balance, eth_balance, block_number });
}
