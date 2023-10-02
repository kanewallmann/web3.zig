const std = @import("std");

const web3 = @import("web3.zig");

/// Returns an approximate float value in ether for the given amount of wei
pub inline fn floatFromWei(val: anytype) f64 {
    return web3.Ether.wrap(val).toFloat();
}

/// Formats the given wei value as a string and writes it into the buffer
pub fn formatEtherBuf(out: []u8, value: u256) !void {
    var fbs = std.io.fixedBufferStream(out);
    return web3.Ether.wrap(value).toString(fbs.writer());
}

/// Formats the given wei value as a string into the given writer
pub fn formatEther(value: u256, writer: anytype) !void {
    return web3.Ether.wrap(value).toString(writer);
}

/// Returns the keccak256 digest of the supplied bytes
pub fn keccak256(input: []const u8) web3.Hash {
    var output: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(input, output[0..], .{});
    return web3.Hash.wrap(&output);
}

/// Returns the sha256 digest of the supplied bytes
pub fn sha256(input: []const u8) web3.Hash {
    var output: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, output[0..], .{});
    return web3.Hash.wrap(&output);
}
