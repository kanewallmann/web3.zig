const std = @import("std");

const web3 = @import("web3");

const abi_json = @embedFile("erc20.json");

const addr = web3.Address.fromString("0xf977814e90da44bfa03b6295a0616a897441acec") catch unreachable; // Binance wallet
const usdt = web3.Address.fromString("0xdac17f958d2ee523a2206206994597c13d831ec7") catch unreachable;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.detectLeaks();
    var allocator = gpa.allocator();

    // Get rpc endpoint from first arg
    var args = try std.process.argsWithAllocator(allocator);
    _ = args.next(); // Skip exe name
    const rpc_endpoint = args.next() orelse @panic("Supply RPC endpoint as first argument");

    // Init a provider
    var json_rpc_provider = try web3.JsonRpcProvider.init(allocator, try std.Uri.parse(rpc_endpoint));
    defer json_rpc_provider.deinit();

    // Parse the ABI from the json file
    var abi = try web3.abi.parseJson(allocator, abi_json);
    defer abi.deinit(allocator);

    // Create a contract utility
    const contract = web3.Contract.init(allocator, usdt, abi, json_rpc_provider.provider());

    // Call balanceOf(addr)
    const return_values = try contract.call("balanceOf", .{addr}, .{ .from = addr });
    defer allocator.free(return_values.data);
    // Return values can be retrieved by name `getNamed` or by position `get`
    const usdt_balance = web3.FixedPoint(8, u256).wrap(try return_values.getNamed(allocator, "balance", u256));

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
    std.debug.print("\n{} has {d:.6} USDT and {:.5} ETH at block {:}\n", .{ addr, usdt_balance, eth_balance, block_number });
}
