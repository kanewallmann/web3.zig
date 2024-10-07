const std = @import("std");

const web3 = @import("web3");

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

    // Get a random block (include full transactions)
    var block = try json_rpc_provider.getBlockByNumber(.{ .number = 18255315 }, true);
    defer block.deinit(allocator);

    // Print the results
    std.debug.print("\n{any}\n", .{block});
}
