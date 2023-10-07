const std = @import("std");

const web3 = @import("web3");

const reth = web3.Address.fromString("0xae78736Cd615f374D3085123A210448E74Fc6393") catch unreachable;

const rETH = struct {
    pub const events = struct {
        pub const TokensBurned = struct {
            pub const topic = web3.Hash.wrap(web3.abi.computeTopicFromSig("TokensBurned(address,uint256,uint256,uint256)") catch unreachable);
            pub const returnType = struct { address: web3.Indexed(web3.Address), reth: web3.Ether, eth: web3.Ether };
        };
    };
};

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

    // // Create a topic filter
    const topics = [_]web3.Hash{
        rETH.events.TokensBurned.topic,
    };

    // Get the logs
    var logs = try json_rpc_provider.getLogs(from_block, null, reth, topics[0..]);
    defer logs.deinit(allocator);

    // Decode and display results
    for (logs.raw) |log| {
        const decoded_log = try web3.abi.decodeLog(allocator, log, rETH.events.TokensBurned.returnType);

        // FixedPoint (and Ether) types support the precision option when formating values
        std.debug.print("{} burned {d:.6} rETH for {d:.6} ETH\n", .{ decoded_log.address, decoded_log.reth, decoded_log.eth });
    }
}
