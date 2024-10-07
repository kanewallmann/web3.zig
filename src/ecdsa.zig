const std = @import("std");
const curve = std.crypto.ecc.Secp256k1;
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const web3 = @import("web3.zig");

/// Represents an ECDSA signing key on the Secp256k1 curve
pub const SigningKey = struct {
    const Self = @This();

    privkey: [32]u8,

    /// Wraps existing memory into this type
    pub inline fn wrap(privkey: [32]u8) Self {
        return Self{
            .privkey = privkey,
        };
    }

    /// Converts a hex encoded string into a signing key
    pub fn fromString(privkey_: []const u8) !Self {
        var privkey = privkey_;

        if (privkey.len == 66 and privkey[0] == '0' and privkey[1] == 'x') {
            privkey = privkey[2..];
        }

        if (privkey.len != 64) {
            return error.InvalidLength;
        }

        var raw: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&raw, privkey);
        return wrap(raw);
    }

    /// Calculates an Ethereum address from the signing key
    pub fn toAddress(self: Self) !web3.Address {
        return web3.Address.fromUncompressedSec1(try self.toPubkeyUncompressedSec1());
    }

    /// Calcultes pubkey and returns in compressed SEC1 format
    pub fn toPubkeyCompressedSec1(self: Self) ![33]u8 {
        const pubkey = try curve.mul(curve.basePoint, self.privkey, .big);
        return pubkey.toCompressedSec1();
    }

    /// Calcultes pubkey and returns in uncompressed SEC1 format
    pub fn toPubkeyUncompressedSec1(self: Self) ![65]u8 {
        const pubkey = try curve.mul(curve.basePoint, self.privkey, .big);
        return pubkey.toUncompressedSec1();
    }

    /// Signs the given message and returns a signature
    pub fn sign(self: Self, message: []const u8) !Signature {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(message, &hash, .{});
        const z = hashToScalar(hash);

        var r: curve.scalar.Scalar = undefined;
        var s: curve.scalar.Scalar = undefined;
        var y_parity: bool = false;

        const da = curve.scalar.Scalar.fromBytes(self.privkey, .big) catch return error.InvalidPrivateKey;

        var counter: usize = 0;
        while (true) : (counter += 1) {
            const k_bytes = self.generateNonce(message, counter);
            var k = try curve.scalar.Scalar.fromBytes(k_bytes, .big);

            // Compute curve point
            const p1 = (curve.basePoint.mul(k.toBytes(.little), .little) catch continue).affineCoordinates();
            r = curve.scalar.Scalar.fromBytes(p1.x.toBytes(.little), .little) catch unreachable;
            if (r.isZero()) {
                continue;
            }

            y_parity = p1.y.isOdd();

            // Compute s value (s = k^-1(z + r * d_a))
            const kinv = k.invert();
            s = kinv.mul(z.add(da.mul(r)));

            // Check if signature is valid
            if (!s.isZero()) {
                break;
            }
        }

        // Encode into VRS format
        var signature: Signature = undefined;

        var bytes = r.toBytes(native_endian);
        signature.r = std.mem.readInt(u256, &bytes, .little);

        bytes = s.toBytes(native_endian);
        signature.s = std.mem.readInt(u256, &bytes, .little);

        signature.v = @as(u256, if (y_parity) 1 else 0);

        return signature;
    }

    /// Generates a deterministic k value per RFC 6979 for deterministic signature generation.
    /// counter can be incremented if the output k results in an invalid signature to try the next possible k.
    fn generateNonce(self: Self, message: []const u8, counter: usize) [32]u8 {
        const hmac = std.crypto.auth.hmac.sha2.HmacSha256;

        // 3.2.a
        var h1: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(message, &h1, .{});

        var v: [33]u8 = undefined;
        var k: [32]u8 = undefined;
        var input: [97]u8 = undefined;

        // 3.2.b
        @memset(v[0..32], 0x01);
        v[32] = 0;

        // 3.2.c
        @memset(&k, 0x00);

        // 3.2.d
        @memcpy(input[0..32], v[0..32]);
        input[32] = 0x00;
        @memcpy(input[33..65], &self.privkey);
        @memcpy(input[65..97], &h1);
        hmac.create(&k, &input, &k);

        // 3.2.e
        hmac.create(v[0..32], v[0..32], &k);

        // 3.2.f
        @memcpy(input[0..32], v[0..32]);
        input[32] = 0x01;
        @memcpy(input[33..65], &self.privkey);
        @memcpy(input[65..97], &h1);
        hmac.create(&k, &input, &k);

        // 3.2.g
        hmac.create(v[0..32], v[0..32], &k);

        // 3.2.h
        hmac.create(v[0..32], v[0..32], &k);

        var i: usize = 0;
        while (true) : (i += 1) {
            const k_int = std.mem.readInt(u256, v[0..32], .big);

            if (i >= counter and k_int > 0 and k_int < curve.scalar.field_order) {
                break;
            }

            hmac.create(&k, v[0..33], &k);
            hmac.create(v[0..32], v[0..32], &k);
        }

        return v[0..32].*;
    }
};

/// Represents an ECDSA signature on the Secp256k1 curve in the VRS format Ethereum uses
pub const Signature = struct {
    const Self = @This();

    v: u256, // Recovery ID
    r: u256,
    s: u256,

    /// Updates the v value of this signature to encode the chain id per EIP-155
    pub fn addChainId(self: *Self, chain_id: u256) !void {
        if (self.v > 1) {
            return error.UnexpectedParity;
        }

        self.v += (2 * chain_id) + 35;
    }

    /// Recovers the chain id encoded in the v value per EIP-155 (or zero if not an EIP-155 signature)
    pub fn getChainId(self: Self) u256 {
        if (self.v > 35) {
            var v = self.v - 35;
            v -= @rem(v, 2);
            return v / 2;
        }
        return 0;
    }

    /// Verifies that the given signature is valid for the given message and pubkey.
    /// Public key can be either compressed or uncompressed SEC1 encoded.
    pub fn verify(self: Self, pubkey: []const u8, message: []const u8) !bool {
        // Reconstruct r and s field elements
        var r_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &r_bytes, self.r, .little);
        var r = curve.scalar.Scalar.fromBytes(r_bytes, .little) catch return false;

        var s_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &s_bytes, self.s, .little);
        var s = curve.scalar.Scalar.fromBytes(s_bytes, .little) catch return false;

        // Hash message
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(message, &hash, .{});
        const z = hashToScalar(hash);

        // Compute u1 and u2
        const sinv = s.invert();
        const u_1 = z.mul(sinv);
        const u_2 = r.mul(sinv);

        // Reconstruct pubkey point (ensuring it is on the curve)
        const qa = try curve.fromSec1(pubkey);

        // Check Qa != O
        if (qa.equivalent(curve.identityElement)) {
            return false;
        }

        // Compute (u_1 * G) + (u_2 * qa)
        const p1 = curve.mulDoubleBasePublic(curve.basePoint, u_1.toBytes(.little), qa, u_2.toBytes(.little), .little) catch return false;

        const affine = p1.affineCoordinates();
        const affine_bytes = affine.x.toBytes(.big);
        const scalar = curve.scalar.Scalar.fromBytes(affine_bytes, .big) catch unreachable;

        // Check if r is congruent to x1 mod N
        return r.equivalent(scalar);
    }

    /// Recovers an address from a signature and message
    pub fn recoverAddress(self: Self, message: []const u8) !web3.Address {
        const pubkey = try recoverPubkey(self, message);
        return try web3.Address.fromUncompressedSec1(pubkey);
    }

    /// Recovers an uncompressed SEC1 encoded pubkey from a signature and message
    pub fn recoverPubkey(self: Self, message: []const u8) ![65]u8 {
        // Reconstruct r and s field elements
        var r_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &r_bytes, self.r, .little);
        var r = try curve.scalar.Scalar.fromBytes(r_bytes, .little);

        var s_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &s_bytes, self.s, .little);
        var s = try curve.scalar.Scalar.fromBytes(s_bytes, .little);

        // Hash message
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(message, &hash, .{});
        const z = hashToScalar(hash);

        // Compute u1 and u2
        const rinv = r.invert();
        const u_1 = z.mul(rinv).neg();
        const u_2 = s.mul(rinv);

        const is_odd = (self.v % 2) == 1;

        // Reconstruct curve point R
        const r_fe = try curve.Fe.fromBytes(r_bytes, .little);
        const y = try curve.recoverY(r_fe, is_odd);
        const R = try curve.fromAffineCoordinates(.{ .x = r_fe, .y = y });

        // Compute (u_1 * G) + (u_2 * qa)
        const qa = try curve.mulDoubleBasePublic(curve.basePoint, u_1.toBytes(.little), R, u_2.toBytes(.little), .little);

        return qa.toUncompressedSec1();
    }
};

/// Hashes the supplied message to a scalar within the curve main sub group
fn hashToScalar(hash: [32]u8) curve.scalar.Scalar {
    // std.debug.print("Hash = {}\n", .{std.fmt.fmtSliceHexLower(&hash)});

    var z_int = std.mem.readInt(u256, &hash, .big);

    if (z_int < curve.scalar.field_order) {
        return curve.scalar.Scalar.fromBytes(hash, .big) catch unreachable;
    }

    z_int -= curve.scalar.field_order;

    var z_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &z_bytes, z_int, .big);
    return curve.scalar.Scalar.fromBytes(z_bytes, .big) catch unreachable;
}

test "address computation" {
    const assert = std.debug.assert;

    {
        const signing_key = try SigningKey.fromString("320631693565bf68a84069b852bce4616142f4f4c4d16e666d33e0615127b7a4");

        const addr = try signing_key.toAddress();
        var hex: [20]u8 = undefined;
        _ = try std.fmt.hexToBytes(&hex, "41c3e27461d5cb7623ca04aa485118ec6a0706cf");
        assert(std.mem.eql(u8, &addr.raw, &hex));
    }
}

test "signing and recovery" {
    const assert = std.debug.assert;

    const signing_key = try SigningKey.fromString("320631693565bf68a84069b852bce4616142f4f4c4d16e666d33e0615127b7a4");

    const pubkey = try signing_key.toPubkeyUncompressedSec1();

    const message = "Hello, world!";
    const signature = try signing_key.sign(message);
    const valid = try signature.verify(&pubkey, message);

    assert(valid);

    const recovered_addr = try signature.recoverAddress(message);
    const actual_addr = try signing_key.toAddress();

    assert(std.mem.eql(u8, &recovered_addr.raw, &actual_addr.raw));
}

test "eip-155" {
    const allocator = std.testing.allocator;
    const assert = std.debug.assert;

    // Test vector: https://eips.ethereum.org/EIPS/eip-155
    var tx = web3.TransactionRequest{
        .chain_id = 1,
        .nonce = 9,
        .gas_price = 20 * std.math.pow(u256, 10, 9),
        .gas = 21000,
        .to = try web3.Address.fromString("0x3535353535353535353535353535353535353535"),
        .value = std.math.pow(u256, 10, 18),
    };

    const encoded = try tx.encode(allocator);
    defer allocator.free(encoded);

    const signing_key = try SigningKey.fromString("4646464646464646464646464646464646464646464646464646464646464646");

    var sig = try signing_key.sign(encoded);
    try sig.addChainId(tx.chain_id.?);

    tx.addSignature(sig);

    const signed_tx = try tx.encode(allocator);
    defer allocator.free(signed_tx);

    var hex: [1024]u8 = undefined;
    const result = try std.fmt.hexToBytes(&hex, "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");

    assert(std.mem.eql(u8, result, signed_tx));
}
