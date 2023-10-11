//! Implements the bip-39 standard for generatic deterministic keys from mnemonic codes
//! Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

const std = @import("std");

const web3 = @import("web3.zig");

// TODO: Add other languages
/// The default English word list
pub const english = WordList.load(@embedFile("wordlists/english.txt"));

/// Represents a 2048-word word list (assumed to be alphabetical per the bip-39 standard)
pub const WordList = struct {
    const Self = @This();

    words: [2048][]const u8,

    /// Loads a word list from a given new line separated string
    pub fn load(raw: []const u8) Self {
        return Self{
            .words = loadWordList(raw),
        };
    }

    /// Performs a search of the given word and returns it's index.
    /// Returns an error if the word isn't in the list.
    pub fn lookup(self: Self, word: []const u8) !u16 {
        if (word.len == 0) {
            return error.WordNotFound;
        }

        const first_letter = word[0];

        // Binary search on first letter
        var half: u16 = self.words.len / 2;
        var i: u16 = half;

        while (self.words[i][0] != first_letter) {
            const letter = self.words[i][0];

            if (first_letter > letter) {
                half /= 2;
                i += half;
            } else {
                half /= 2;
                i -= half;
            }
        }

        // Scan alphabetically from here
        var j: usize = 1;

        while (j < word.len and self.words[i][j] == word[j]) {
            j += 1;
        }

        if (j == word.len) {
            return i;
        }

        const dir: isize = if (word[j] > self.words[i][j]) 1 else -1;

        while (j < word.len and self.words[i][j - 1] == word[j - 1]) {
            i = @intCast(@as(isize, @intCast(i)) + dir);

            while (j < word.len and j < self.words[i].len and self.words[i][j] == word[j]) {
                j += 1;
            }
        }

        if (j == word.len) {
            return i;
        }

        return error.WordNotFound;
    }

    /// Allocates and returns the entropy encoded in the given mnemonic phrase.
    /// If word count is known at comptime, prefer the `getEntropy` method instead.
    /// Returns an error if the mnemonic contains invalid words or bad checksum.
    pub fn decodeAlloc(self: Self, allocator: std.mem.Allocator, mnemonic: []const u8) ![]u8 {
        var word_count: u16 = 1;
        var i: usize = 0;

        while (i < mnemonic.len) : (i += 1) {
            if (mnemonic[i] == ' ') {
                word_count += 1;
            }
        }

        if (word_count != 12 and word_count != 15 and word_count != 18 and word_count != 21 and word_count != 24) {
            return error.InvalidMnemonic;
        }

        const checksum_bits: u16 = word_count / 3;
        const entropy_bits: u16 = @intCast(word_count * 11 - checksum_bits);
        const entropy_bytes: u16 = std.math.divCeil(u16, entropy_bits, 8) catch unreachable;

        var out = try allocator.alloc(u8, entropy_bytes);
        errdefer allocator.free(out);

        switch (word_count) {
            12 => @memcpy(out, &(try self.decode(12, mnemonic))),
            15 => @memcpy(out, &(try self.decode(15, mnemonic))),
            18 => @memcpy(out, &(try self.decode(18, mnemonic))),
            21 => @memcpy(out, &(try self.decode(21, mnemonic))),
            24 => @memcpy(out, &(try self.decode(24, mnemonic))),
            else => unreachable,
        }

        return out;
    }

    /// Validates the given mnemonic is valid (contains correct number of words and checksum is correct) and returns true if so
    pub fn validate(self: Self, mneomnic: []const u8) bool {
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        var allocator = gpa.allocator();

        var entropy = self.decodeAlloc(allocator, mneomnic) catch return false;
        allocator.free(entropy);

        return true;
    }

    /// Decodes a given 12,15,18,21,24 word mnemonic phrase encoded in bip-39 format and returns the entropy.
    /// Returns an error if the mnemonic contains invalid words or bad checksum.
    pub fn decode(self: Self, comptime word_count: comptime_int, mnemonic: []const u8) ![(word_count * 11 - word_count / 3) / 8]u8 {
        if (word_count != 12 and word_count != 15 and word_count != 18 and word_count != 21 and word_count != 24) {
            @compileError("Invalid word count");
        }

        const checksum_bits: u16 = comptime word_count / 3;
        const entropy_bits: u16 = @intCast(word_count * 11 - checksum_bits);
        const entropy_bytes: u16 = comptime std.math.divCeil(u16, entropy_bits, 8) catch unreachable;

        var buffer = mnemonic;
        var out: [entropy_bytes + 1]u8 = .{0} ** (entropy_bytes + 1);

        var i: usize = 0;
        var offset: usize = 0;

        while (buffer.len > 0 and i < word_count) : (i += 1) {
            // Iterate to next space (or eof)
            var word_len: usize = 0;
            while (word_len < buffer.len and buffer[word_len] != ' ') : (word_len += 1) {}

            // Lookup word index
            const word = buffer[0..word_len];
            var index: u16 = @intCast(try self.lookup(word));

            // Loop over words and append each 11 bit value to the buffer
            var in_bits_remaining: usize = 11;
            while (in_bits_remaining > 0) {
                const byte_index = offset / 8;
                const out_bit_offset = @rem(offset, 8);
                const bits_remaining = 8 - out_bit_offset;

                const in_bit_offset: isize = @as(isize, @intCast(in_bits_remaining)) - 8 + @as(isize, @intCast(out_bit_offset));
                var in_val: u8 = undefined;

                if (in_bit_offset > 0) {
                    in_val = @truncate(index >> @intCast(in_bit_offset));
                } else if (in_bit_offset < 0) {
                    in_val = @truncate(index << @intCast(-in_bit_offset));
                    in_val &= @truncate(@as(u8, 255) << @intCast(-in_bit_offset));
                } else {
                    in_val = @truncate(index);
                }

                out[byte_index] |= in_val;

                if (in_bits_remaining < bits_remaining) {
                    offset += in_bits_remaining;
                    in_bits_remaining = 0;
                } else {
                    in_bits_remaining -= bits_remaining;
                    offset += bits_remaining;
                }
            }

            // Chop word off buffer and repeat
            if (word_len == buffer.len) {
                buffer = buffer[word_len..];
            } else {
                buffer = buffer[word_len + 1 ..];
            }
        }

        // Check we consumed correct number of words
        if (i != word_count or buffer.len != 0) {
            return error.InvalidMnemonic;
        }

        const entropy = out[0..entropy_bytes].*;
        const checksum = out[entropy_bytes];

        // Check checksum is correct
        const hash = web3.sha256(&entropy);
        const expected_checksum = hash.raw[0] & ((std.math.pow(u16, 2, checksum_bits) - 1) << (8 - checksum_bits));
        if (checksum != expected_checksum) {
            return error.InvalidChecksum;
        }

        return entropy;
    }
};

// TODO: Support passphrases
/// Calculates the bip-39 seed from the given mnemonic phrase
pub fn seedFromMnemonic(mnemonic: []const u8) ![64]u8 {
    var out: [64]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&out, mnemonic, "mnemonic", 2048, std.crypto.auth.hmac.sha2.HmacSha512);
    return out;
}

/// Reads a BIP-39 list from a newline separated string
fn loadWordList(raw: []const u8) [2048][]const u8 {
    @setEvalBranchQuota(1024 * 1024);

    var word_list_arr: [2048][]const u8 = undefined;
    var buffer = raw;

    var i: usize = 0;
    while (true) : (i += 1) {
        var j: usize = 0;
        while (j < buffer.len and buffer[j] != '\n') : (j += 1) {}
        word_list_arr[i] = buffer[0..j];

        if (buffer.len == j) {
            break;
        }

        buffer = buffer[j + 1 ..];
    }

    return word_list_arr;
}

test "mnemonic" {
    const assert = std.debug.assert;
    const allocator = std.testing.allocator;

    assert(english.validate("rose update response coin cream column wine timber lens repeat short trial mean pear conduct jealous ready negative mind army dance pulse noise capable"));
    assert(english.validate("opinion soldier planet cloth swarm polar negative hub will scene maid exotic love chuckle essay casino alcohol bird reward weird intact"));
    assert(english.validate("lottery sun canoe enjoy direct early champion dismiss tomorrow strategy scheme shell middle crouch head raven cement bring"));
    assert(english.validate("robot need ribbon wink hard dice space immune equal tell castle grant fun absent pond"));
    assert(english.validate("cat arch host enforce mixture agent weapon salon praise soldier scout dismiss"));

    var entropy = try english.decodeAlloc(allocator, "cat arch host enforce mixture agent weapon salon praise soldier scout dismiss");
    allocator.free(entropy);
}

test "word list" {
    const assert = std.debug.assert;

    {
        const k = try english.lookup("spike");
        assert(k == 1678);
    }

    {
        const k = try english.lookup("prepare");
        assert(k == 1359);
    }

    {
        const k = try english.lookup("zoo");
        assert(k == 2047);
    }

    {
        const k = try english.lookup("abandon");
        assert(k == 0);
    }
}
