const std = @import("std");

const web3 = @import("web3");

const reth = web3.Address.fromString("0xae78736Cd615f374D3085123A210448E74Fc6393") catch unreachable;

const reth_abi_json = @embedFile("reth.json");

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

    // Search in the past 10,000 blocks
    var block = try json_rpc_provider.getBlockNumber();
    var from_block = web3.BlockTag{
        .number = block - 10000,
    };

    // Parse the ABI file
    var abi = try web3.abi.parseJson(allocator, reth_abi_json);
    defer abi.deinit(allocator);

    // Find the desired event
    const event_entry = try abi.findFirstEntry("TokensBurned");
    if (event_entry == null) @panic("ABI missing required entry");

    // Create a topic filter
    const ether_deposited_topic = try event_entry.?.computeTopic();
    const topics = [_]web3.Hash{
        ether_deposited_topic,
    };

    // Get the logs
    var logs = try json_rpc_provider.getLogs(from_block, null, reth, topics[0..]);
    defer logs.deinit(allocator);

    // Manually decode and display results
    for (logs.raw) |log| {
        const from = try web3.abi.decodeArg(allocator, &log.topics[1].raw, 0, web3.AbiType.address, web3.Address);
        const amount_reth = web3.Ether.wrap(try web3.abi.decodeArg(allocator, log.data.raw, 0, web3.AbiType.uint256, u256));
        const amount_eth = web3.Ether.wrap(try web3.abi.decodeArg(allocator, log.data.raw, 32, web3.AbiType.uint256, u256));

        // FixedPoint (and Ether) types support the precision option when formating values
        std.debug.print("{} burned {d:.6} rETH for {d:.6} ETH\n", .{ from, amount_reth, amount_eth });
    }
}
