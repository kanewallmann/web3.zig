//! Implements the bip-32 standard for "HD Wallets"
//! Reference: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

const std = @import("std");
const curve = std.crypto.ecc.Secp256k1;

const web3 = @import("web3.zig");

const secret_key = "Bitcoin seed";

pub const Node = struct {
    const Self = @This();

    key: [32]u8,
    chain_code: [32]u8,
    recovery: u8, // Used on neutered nodes as the 1st byte of the public key in SEC1 compressed form

    /// Returns true if the node has been "neutered" i.e. private key has been discarded
    pub fn isNeutered(self: Self) bool {
        return self.recovery != 0;
    }

    /// Constructs a master node from the given seed (typically a 256 byte output of mnemonic.seedFromMnemonic)
    pub fn fromSeed(seed: []const u8) Self {
        // Calculate I = HMAC-SHA512("Bitcoin seed", S)
        const hmac = std.crypto.auth.hmac.sha2.HmacSha512;
        var out: [64]u8 = undefined;
        hmac.create(&out, seed, secret_key);

        // Split I into two 32-byte sequences, IL and IR.
        return Self{
            .recovery = 0,
            .key = out[0..32].*,
            .chain_code = out[32..64].*,
        };
    }

    /// Returns a node from the given seed and derivation path e.g. m/44'/60'/0'/0
    pub fn fromSeedAndPath(seed: []const u8, path: []const u8) !Self {
        if (path[0] != 'm') {
            return error.InvalidPath;
        }

        const master_node = fromSeed(seed);
        return master_node.derivePath(path[1..]);
    }

    /// Gets the private key for this node. Errors if the node is "neutered".
    pub fn getPrivateKey(self: Self) ![32]u8 {
        if (self.recovery == 0) {
            return self.key;
        } else {
            return error.PrivateKeyNotAvailable;
        }
    }

    /// Gets the public key for this node
    pub fn getPublicKey(self: Self) ![33]u8 {
        if (self.recovery == 0) {
            const pubkey = try curve.mul(curve.basePoint, self.key, .Big);
            return pubkey.toCompressedSec1();
        } else {
            var pubkey: [33]u8 = undefined;
            pubkey[0] = self.recovery;
            @memcpy(pubkey[1..33], &self.key);
            return pubkey;
        }
    }

    /// Derives a node from the given string-encoded path e.g. /44'/60'/0'/0
    pub fn derivePath(self: Self, path: []const u8) !Self {
        if (path.len == 0) {
            return self;
        }

        var path_slice = path;

        var node = self;

        while (path_slice.len > 0 and path_slice[0] == '/') {
            path_slice = path_slice[1..];

            var i: usize = 0;
            while (i < path_slice.len and std.ascii.isDigit(path_slice[i])) {
                i += 1;
            }

            var hardened = false;
            if (i < path_slice.len and path_slice[i] == '\'') {
                hardened = true;
            }

            var index = std.fmt.parseInt(u32, path_slice[0..i], 10) catch unreachable;

            if (hardened) {
                index += std.math.pow(u32, 2, 31);
                i += 1;
            }

            node = try node.derive(index);

            path_slice = path_slice[i..];
        }

        if (path_slice.len != 0) {
            return error.InvalidPath;
        }

        return node;
    }

    /// Returns the child node at given index. Returns an error if the derived key
    /// is not a valid curve point. In which case, the next i should be used.
    /// Returns an error if trying to derive a child key with a neutered node and
    /// the child key is hardened.
    pub fn derive(self: Self, i: u32) !Self {
        if (self.recovery == 0) {
            return self.dervivePrivate(i);
        } else {
            return self.dervivePublic(i);
        }
    }

    fn dervivePublic(self: Self, i: u32) !Self {
        if (i >= std.math.pow(u32, 2, 31)) {
            return error.CannotDeriveHardenedChild;
        }

        const hmac = std.crypto.auth.hmac.sha2.HmacSha512;
        var out: [64]u8 = undefined;
        var in: [37]u8 = undefined;

        // Data = ser_P(K_par) || ser_32(i)
        in[0] = self.recovery;
        @memcpy(in[1..33], &self.key);
        std.mem.writeIntBig(u32, in[33..][0..4], i);

        // HMAC-SHA512(c_par, Data)
        hmac.create(&out, &in, &self.chain_code);

        // ki = parse_256(IL) + k_par (mod n).
        const kpar = try curve.fromSec1(in[0..33]);
        const pubkey = try curve.mul(curve.basePoint, out[0..32].*, .Big);
        const ki = pubkey.add(kpar);

        const compressed_point = ki.toCompressedSec1();

        return Self{
            .recovery = compressed_point[0],
            .key = compressed_point[1..33].*,
            .chain_code = out[32..64].*,
        };
    }

    fn dervivePrivate(self: Self, i: u32) !Self {
        const hmac = std.crypto.auth.hmac.sha2.HmacSha512;
        var out: [64]u8 = undefined;
        var in: [37]u8 = undefined;

        if (i >= std.math.pow(u32, 2, 31)) {
            // Data = 0x00 || ser_256(k_par) || ser_32(i)).
            in[0] = 0;
            @memcpy(in[1..33], &self.key);
        } else {
            // Data = ser_P(point(k_par)) || ser_32(i)).
            const pubkey = try curve.mul(curve.basePoint, self.key, .Big);
            const compressed_point = pubkey.toCompressedSec1();
            @memcpy(in[0..33], &compressed_point);
        }

        std.mem.writeIntBig(u32, in[33..][0..4], i);

        // HMAC-SHA512(c_par, Data)
        hmac.create(&out, &in, &self.chain_code);

        const il = try curve.scalar.Scalar.fromBytes(out[0..32].*, .Big);
        const kpar = try curve.scalar.Scalar.fromBytes(self.key, .Big);
        const ki = il.add(kpar);

        return Self{
            .recovery = 0,
            .key = ki.toBytes(.Big),
            .chain_code = out[32..64].*,
        };
    }

    /// Returns a "neutered" version of this node that is capable of deriving child pubkeys
    /// but not child privkeys
    pub fn neuter(self: Self) !Self {
        const pubkey = try curve.mul(curve.basePoint, self.key, .Big);
        const compressed_point = pubkey.toCompressedSec1();

        return Self{
            .recovery = compressed_point[0],
            .key = compressed_point[1..33].*,
            .chain_code = self.chain_code,
        };
    }
};

test "neutering" {
    const assert = std.debug.assert;

    const seed = try web3.mnemonic.seedFromMnemonic("rose update response coin cream column wine timber lens repeat short trial mean pear conduct jealous ready negative mind army dance pulse noise capable");
    const master_node = Node.fromSeed(&seed);

    // Derive m/0
    const node = try master_node.derive(0);

    // Derive m/0/1
    const child = try node.derive(1);

    // Neuter node and derive m/0/1
    const neutered_node = try node.neuter();
    const neutered_child = try neutered_node.derive(1);

    // Neutered node should produce same public key
    assert(std.mem.eql(u8, &try child.getPublicKey(), &try neutered_child.getPublicKey()));
}

test "path derivation" {
    const assert = std.debug.assert;

    const seed = try web3.mnemonic.seedFromMnemonic("rose update response coin cream column wine timber lens repeat short trial mean pear conduct jealous ready negative mind army dance pulse noise capable");
    const account_node = try Node.fromSeedAndPath(&seed, "m/44'/0'/0'/0");

    const node = try account_node.derive(0);

    var hex_priv: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hex_priv, "cbc3ab34be3c6e627420a33ffbc296ea409770ec0cbfdba084f111d7b8be472c");
    assert(std.mem.eql(u8, &try node.getPrivateKey(), &hex_priv));

    var hex_pub: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hex_pub, "03e6f48804f69f7c17949de28ea65d2bfe16d4af206d854099d23297dd2a490c15");
    assert(std.mem.eql(u8, &try node.getPublicKey(), &hex_pub));
}
