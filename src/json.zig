const std = @import("std");

const web3 = @import("web3.zig");

/// Encodes data into JSON
pub const JsonWriter = struct {
    pub fn writeLiteral(arg: []const u8, writer: anytype) !usize {
        return writer.write(arg);
    }

    pub fn writeString(arg: []const u8, writer: anytype) !usize {
        try writer.writeByte('"');
        _ = try writer.write(arg);
        try writer.writeByte('"');
        return arg.len + 2;
    }

    pub fn writeHexString(arg: []const u8, writer: anytype) !usize {
        const charset = "0123456789abcdef";
        _ = try writer.write("\"0x");
        for (arg) |b| {
            try writer.writeByte(charset[b >> 4]);
            try writer.writeByte(charset[b & 15]);
        }
        try writer.writeByte('"');
        return 4 + arg.len / 2;
    }

    pub fn writeHexInt(arg: anytype, writer: anytype) !usize {
        var buffer: [78]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);
        try std.fmt.formatInt(arg, 16, .lower, .{}, fbs.writer());

        _ = try writer.write("\"0x");
        _ = try writer.write(buffer[0..fbs.pos]);
        try writer.writeByte('"');

        return fbs.pos + 4;
    }

    pub fn write(arg: anytype, writer: anytype) !usize {
        const T = @TypeOf(arg);
        const TI = @typeInfo(T);

        if (TI == .@"struct" or TI == .@"union") {
            if (@hasDecl(T, "toJson")) {
                return arg.toJson(writer);
            }
        }

        switch (TI) {
            .int, .comptime_int => {
                return writeHexInt(arg, writer);
            },
            .float, .comptime_float => {
                var buffer: [78]u8 = undefined;
                const fbs = std.io.fixedBufferStream(&buffer);
                try std.fmt.format(writer, "{d}", .{arg});
                return writer.write(buffer[0..fbs.pos]);
            },
            .null => {
                return writer.write("null");
            },
            .optional => {
                if (arg == null) {
                    return write(null, writer);
                } else {
                    return write(arg.?, writer);
                }
            },
            .bool => {
                if (arg) {
                    return writer.write("true");
                } else {
                    return writer.write("false");
                }
            },
            .void, .noreturn => {
                return;
            },
            .array => |arr| {
                const slice: []const arr.child = arg[0..];
                return write(slice, writer);
            },
            .@"struct" => |struct_t| {
                if (struct_t.is_tuple) {
                    try writer.writeByte('[');

                    var total_size: usize = 2;

                    var first = comptime true;
                    inline for (struct_t.fields) |field| {
                        if (@typeInfo(field.type) != .optional or @field(arg, field.name) != null) {
                            if (!first) {
                                try writer.writeByte(',');
                                total_size += 1;
                            }
                            first = false;

                            const value = @field(arg, field.name);

                            total_size += try write(&value, writer);
                        }
                    }

                    try writer.writeByte(']');
                    return total_size;
                } else {
                    try writer.writeByte('{');

                    var total_size: usize = 2;

                    var first = comptime true;
                    inline for (struct_t.fields) |field| {
                        const val_ptr = &@field(arg, field.name);

                        if (@typeInfo(field.type) != .optional or val_ptr.* != null) {
                            if (!first) {
                                try writer.writeByte(',');
                                total_size += 1;
                            }
                            first = false;

                            try writer.writeByte('"');
                            const json_def = getJsonDef(T, field.name);
                            total_size += try writer.write(json_def.field_name);

                            _ = try writer.write("\":");
                            total_size += try write(val_ptr, writer);

                            total_size += 3;
                        }
                    }

                    try writer.writeByte('}');
                    return total_size;
                }
            },
            .pointer => |ptr| {
                switch (ptr.size) {
                    .One => {
                        return write(arg.*, writer);
                    },
                    .Slice => {
                        // if (ptr.child == u8) {
                        //     const charset = "0123456789abcdef";
                        //     _ = try writer.write("\"0x");
                        //     for (arg) |b| {
                        //         try writer.writeByte(charset[b >> 4]);
                        //         try writer.writeByte(charset[b & 15]);
                        //     }
                        //     try writer.writeByte('"');
                        //     return 4 + arg.len / 2;
                        // } else {
                        const len = arg.len;
                        try writer.writeByte('[');

                        var total_size: usize = 2;

                        for (0..len) |i| {
                            total_size += try write(arg[i], writer);
                            if (i != len - 1) {
                                try writer.writeByte(',');
                                total_size += 1;
                            }
                        }

                        try writer.writeByte(']');
                        return total_size;
                        // }
                    },
                    .Many, .C => {
                        if (ptr.sentinel == null) {
                            @compileError("Cannot serialize many pointer with no sentinel");
                        }
                        const slice = std.mem.span(arg);
                        return write(slice, writer);
                    },
                }
            },
            else => {
                @compileLog("Type serialization not implemented: ", T);
                @compileError("Cannot serialize value");
            },
        }

        return 0;
    }
};

/// Reads JSON from a buffer and decodes it into desired format
pub const JsonReader = struct {
    const Field = struct {
        key: []const u8,
        value: []const u8,
    };

    fn parseInt(buffer: *[]const u8, comptime T: type) !T {
        var _buffer = buffer.ptr;
        defer {
            buffer.len = buffer.len - (@intFromPtr(_buffer) - @intFromPtr(buffer.ptr));
            buffer.ptr = _buffer;
        }

        const end = _buffer + buffer.len;

        var state: enum { start, zero, hex, decimal } = .start;
        var int_type: enum { decimal, hex } = undefined;
        var string = false;

        while (_buffer != end) : (_buffer += 1) {
            switch (state) {
                .start => {
                    switch (_buffer[0]) {
                        '"' => {
                            string = true;
                        },
                        '0' => {
                            state = .zero;
                        },
                        '1'...'9', '-' => {
                            state = .decimal;
                            int_type = .decimal;
                        },
                        else => return error.UnexpectedCharacter,
                    }
                },
                .zero => {
                    switch (_buffer[0]) {
                        '"' => {
                            _buffer += 1;
                            break;
                        },
                        'x' => {
                            state = .hex;
                            int_type = .hex;
                        },
                        '1'...'9' => {
                            state = .decimal;
                        },
                        else => {
                            break;
                        },
                    }
                },
                .decimal => {
                    switch (_buffer[0]) {
                        '"' => {
                            _buffer += 1;
                            break;
                        },
                        '0'...'9' => {},
                        else => {
                            break;
                        },
                    }
                },
                .hex => {
                    switch (_buffer[0]) {
                        '"' => {
                            _buffer += 1;
                            break;
                        },
                        '0'...'9', 'a'...'f', 'A'...'F' => {},
                        else => {
                            break;
                        },
                    }
                },
            }
        }

        const size: usize = @intFromPtr(_buffer) - @intFromPtr(buffer.ptr);
        var slice = buffer.*[0..size];

        if (string) {
            slice = slice[1 .. slice.len - 1];
        }

        switch (int_type) {
            .hex => {
                return try std.fmt.parseInt(T, slice[2..], 16);
            },
            .decimal => {
                return try std.fmt.parseInt(T, slice, 10);
            },
        }
    }

    fn parseFloat(buffer: *[]const u8, comptime T: type) !T {
        var _buffer = buffer.ptr;
        defer {
            buffer.len = buffer.len - (@intFromPtr(_buffer) - @intFromPtr(buffer.ptr));
            buffer.ptr = _buffer;
        }

        const end = _buffer + buffer.len;

        var state: enum { start, int, frac } = .start;

        while (_buffer != end) : (_buffer += 1) {
            switch (state) {
                .start => {
                    switch (_buffer[0]) {
                        '0'...'9', '-' => {
                            state = .int;
                        },
                        else => return error.UnexpectedCharacter,
                    }
                },
                .int => {
                    switch (_buffer[0]) {
                        '.' => {
                            state = .frac;
                        },
                        '0'...'9' => {},
                        else => {
                            break;
                        },
                    }
                },
                .frac => {
                    switch (_buffer[0]) {
                        '0'...'9' => {},
                        else => {
                            break;
                        },
                    }
                },
            }
        }

        const size: usize = @intFromPtr(_buffer) - @intFromPtr(buffer.ptr);
        const slice = buffer.*[0..size];
        return try std.fmt.parseFloat(T, slice);
    }

    fn parseString(buffer: *[]const u8) ![]const u8 {
        var _buffer = buffer.*;
        defer {
            buffer.* = _buffer;
        }
        var end: usize = 1;
        while (_buffer.len - end != 0 and _buffer[end] != '"') {
            end += 1;
        }
        if (_buffer.len - end == 0) {
            return error.EndOfBuffer;
        }
        _buffer = _buffer[end + 1 ..];
        return buffer.*[1..end];
    }

    fn parseStruct(allocator: std.mem.Allocator, buffer: *[]const u8, comptime T: type) !T {
        var _buffer = buffer.*;
        defer {
            buffer.* = _buffer;
        }

        if (_buffer.len == 0) {
            return error.EndOfBuffer;
        }

        if (_buffer[0] != '{') {
            return error.ExpectedObject;
        }

        _buffer = _buffer[1..];

        var result: T = undefined;

        const TI = @typeInfo(T);

        var field_exists: [TI.@"struct".fields.len]bool = .{false} ** TI.@"struct".fields.len;

        while (_buffer.len > 0) {
            skipWhitespace(&_buffer);

            const key = try parseString(&_buffer);

            skipWhitespace(&_buffer);

            if (_buffer[0] != ':') {
                return error.ExpectedColon;
            }

            _buffer = _buffer[1..];

            skipWhitespace(&_buffer);

            var exists = false;
            inline for (TI.@"struct".fields, 0..) |field, i| {
                const json_def = getJsonDef(T, field.name);

                if (std.mem.eql(u8, json_def.field_name, key)) {
                    @field(result, field.name) = try parse(allocator, &_buffer, field.type);
                    field_exists[i] = true;
                    exists = true;
                    break;
                }
            }

            if (!exists) {
                try parseAny(allocator, &_buffer);
            }

            skipWhitespace(&_buffer);

            if (_buffer.len == 0) {
                return error.EndOfBuffer;
            }

            if (_buffer[0] == '}') {
                break;
            }

            if (_buffer[0] != ',') {
                return error.ExpectedComma;
            }

            _buffer = _buffer[1..];
        }

        if (_buffer.len == 0) {
            return error.EndOfBuffer;
        }

        if (_buffer[0] != '}') {
            return error.ExpectedObjectClose;
        }

        inline for (TI.@"struct".fields, 0..) |field, i| {
            if (!field_exists[i]) {
                const FTI = @typeInfo(field.type);
                if (field.default_value) |default| {
                    const default_value = @as(*field.type, @constCast(@alignCast(@ptrCast(default)))).*;
                    @field(result, field.name) = default_value;
                } else {
                    if (FTI != .optional) {
                        return error.MissingRequiredField;
                    } else {
                        @field(result, field.name) = null;
                    }
                }
            }
        }

        _buffer = _buffer[1..];

        return result;
    }

    fn parseTuple(allocator: std.mem.Allocator, buffer: *[]const u8, comptime T: type) !T {
        const TI = @typeInfo(T);
        std.debug.assert(TI == .Struct and TI.Struct.is_tuple);

        var _buffer = buffer.*;
        defer {
            buffer.* = _buffer;
        }

        if (_buffer.len == 0) {
            return error.EndOfBuffer;
        }

        if (_buffer[0] != '{') {
            return error.ExpectedObject;
        }

        _buffer = _buffer[1..];

        var result: T = undefined;

        const field_count = TI.Struct.fields.len;

        inline for (TI.Struct.fields, 0..) |field, i| {
            skipWhitespace(&_buffer);

            @field(result, field.name) = try parse(allocator, &_buffer, field.type);

            skipWhitespace(&_buffer);

            if (_buffer.len == 0) {
                return error.EndOfBuffer;
            }

            if (i == field_count - 1) {
                break;
            }

            if (_buffer[0] == '}') {
                return error.MissingRequiredField;
            }

            if (_buffer[0] != ',') {
                return error.ExpectedComma;
            }

            _buffer = _buffer[1..];
        }

        if (_buffer[0] != '}') {
            return error.ExpectedObjectClose;
        }

        _buffer = _buffer[1..];

        return result;
    }

    fn parseSlice(allocator: std.mem.Allocator, buffer: *[]const u8, comptime T: type) ![]T {
        var _buffer = buffer.*;
        defer {
            buffer.* = _buffer;
        }

        if (_buffer.len == 0) {
            return error.EndOfBuffer;
        }

        if (_buffer[0] != '[') {
            return error.ExpectedArray;
        }

        _buffer = _buffer[1..];

        skipWhitespace(&_buffer);

        if (_buffer[0] == ']') {
            _buffer = _buffer[1..];
            return allocator.alloc(T, 0);
        }

        var result = std.ArrayList(T).init(allocator);

        while (_buffer.len > 0) {
            skipWhitespace(&_buffer);

            const val = try parse(allocator, &_buffer, T);
            try result.append(val);

            skipWhitespace(&_buffer);

            if (_buffer.len == 0) {
                return error.EndOfBuffer;
            }

            if (_buffer[0] == ']') {
                break;
            }

            if (_buffer[0] != ',') {
                return error.ExpectedComma;
            }

            _buffer = _buffer[1..];
        }

        if (_buffer[0] != ']') {
            return error.ExpectedArrayClose;
        }

        _buffer = _buffer[1..];

        return result.toOwnedSlice();
    }

    fn parseArray(allocator: std.mem.Allocator, buffer: *[]const u8, comptime T: type, comptime L: comptime_int) ![L]T {
        var _buffer = buffer.*;
        defer {
            buffer.* = _buffer;
        }

        if (_buffer.len == 0) {
            return error.EndOfBuffer;
        }

        if (_buffer[0] != '[') {
            return error.ExpectedArray;
        }

        _buffer = _buffer[1..];

        var result: [L]T = undefined;

        for (0..L) |i| {
            skipWhitespace(&_buffer);

            result[i] = try parse(allocator, &_buffer, T);

            skipWhitespace(&_buffer);

            if (i == L - 1) {
                break;
            }

            if (_buffer.len == 0) {
                return error.EndOfBuffer;
            }

            if (_buffer[0] != ',') {
                return error.ExpectedComma;
            }

            _buffer = _buffer[1..];
        }

        if (_buffer[0] != ']') {
            return error.ExpectedArrayClose;
        }

        _buffer = _buffer[1..];

        return result;
    }

    fn parseAnyArray(allocator: std.mem.Allocator, buffer: *[]const u8) !void {
        var _buffer = buffer.*;
        defer {
            buffer.* = _buffer;
        }

        if (_buffer.len == 0) {
            return error.EndOfBuffer;
        }

        if (_buffer[0] != '[') {
            return error.ExpectedArray;
        }

        _buffer = _buffer[1..];

        skipWhitespace(&_buffer);

        if (_buffer[0] == ']') {
            _buffer = _buffer[1..];
            return;
        }

        while (_buffer.len > 0) {
            skipWhitespace(&_buffer);

            try parseAny(allocator, &_buffer);

            skipWhitespace(&_buffer);

            if (_buffer.len == 0) {
                return error.EndOfBuffer;
            }

            if (_buffer[0] == ']') {
                break;
            }

            if (_buffer[0] != ',') {
                return error.ExpectedComma;
            }

            _buffer = _buffer[1..];
        }

        if (_buffer[0] != ']') {
            return error.ExpectedArrayClose;
        }

        _buffer = _buffer[1..];
    }

    /// Skips any type of json value at the cursor (allocator not used)
    fn parseAny(allocator: std.mem.Allocator, buffer: *[]const u8) anyerror!void {
        var _buffer = buffer.*;
        defer {
            buffer.* = _buffer;
        }

        switch (_buffer[0]) {
            '"' => {
                _ = try parseString(&_buffer);
            },
            '0'...'9' => {
                _buffer = _buffer[1..];
                while (_buffer.len > 0 and (_buffer[0] == '.' or std.ascii.isDigit(_buffer[0]))) {
                    _buffer = _buffer[1..];
                }
            },
            '{' => {
                _ = try parseStruct(allocator, &_buffer, struct {});
            },
            '[' => {
                try parseAnyArray(allocator, &_buffer);
            },
            'f', 't' => {
                if (buffer.len >= "true".len and std.mem.eql(u8, buffer.*[0.."true".len], "true")) {
                    _buffer = _buffer["true".len..];
                } else if (buffer.len >= "false".len and std.mem.eql(u8, buffer.*[0.."false".len], "false")) {
                    _buffer = _buffer["false".len..];
                } else {
                    return error.ExpectedValue;
                }
            },
            else => return error.ExpectedValue,
        }
    }

    /// Parses JSON in a supplied buffer into type T
    /// The supplied buffer pointer is moved to the end of the parsed value, make a copy to
    /// avoid losing track of allocation
    /// Caller is responsible for any memory allocated during parsing which may include
    /// deeply nested pointers, an arena allocator can be used to ensure all allocated memory
    /// is freed correctly
    pub fn parse(allocator: std.mem.Allocator, buffer: *[]const u8, comptime T: type) !T {
        const TI = @typeInfo(T);

        skipWhitespace(buffer);

        if (buffer.len == 0) {
            return error.EndOfBuffer;
        }

        if (TI == .@"struct" or TI == .@"union") {
            if (@hasDecl(T, "fromJson")) {
                return T.fromJson(allocator, buffer);
            } else {
                if (@hasDecl(T, "fromString")) {
                    if (buffer.*[0] == '"') {
                        const str = try parseString(buffer);
                        return T.fromString(str);
                    }
                } else if (@hasDecl(T, "fromStringAlloc")) {
                    if (buffer.*[0] == '"') {
                        const str = try parseString(buffer);
                        return try T.fromStringAlloc(allocator, str);
                    }
                } else if (TI == .@"union") {
                    @compileError("Union requries a fromString or fromStringAlloc");
                }
            }
        }

        switch (TI) {
            .int => {
                return parseInt(buffer, T);
            },
            .float => {
                return parseFloat(buffer, T);
            },
            .bool => {
                if (buffer.len >= "true".len and std.mem.eql(u8, buffer.*[0.."true".len], "true")) {
                    buffer.* = buffer.*["true".len..];
                    return true;
                } else if (buffer.len >= "false".len and std.mem.eql(u8, buffer.*[0.."false".len], "false")) {
                    buffer.* = buffer.*["false".len..];
                    return false;
                }
                return error.InvalidBoolean;
            },
            .@"struct" => |struct_t| {
                if (!struct_t.is_tuple) {
                    return try parseStruct(allocator, buffer, T);
                } else {
                    return try parseTuple(allocator, buffer, T);
                }
            },
            .@"union" => {
                return error.ParserError;
            },
            .pointer => |ptr| {
                switch (ptr.size) {
                    .One => {
                        if (@hasDecl(ptr.child, "fromStringAlloc")) {
                            if (buffer.*[0] == '"') {
                                const str = try parseString(buffer);
                                return try ptr.child.fromStringAlloc(allocator, str);
                            }
                        } else {
                            const val = try allocator.create(ptr.child);
                            val.* = try parse(allocator, buffer, ptr.child);
                            return val;
                        }

                        unreachable;
                    },
                    .Many, .C, .Slice => {
                        if (ptr.child == u8 and buffer.*[0] == '"') {
                            const str = try parseString(buffer);
                            const val = try allocator.alloc(u8, str.len);
                            @memcpy(val, str);
                            return val;
                        }

                        return try parseSlice(allocator, buffer, ptr.child);
                    },
                }
            },
            .array => |arr| {
                return try parseArray(allocator, buffer, arr.child, arr.len);
            },
            .optional => |opt| {
                if (buffer.len >= "null".len and std.mem.eql(u8, buffer.*[0.."null".len], "null")) {
                    buffer.* = buffer.*["null".len..];
                    return null;
                }
                return try parse(allocator, buffer, opt.child);
            },
            .@"enum" => |enum_t| {
                if (buffer.*[0] == '"') {
                    const str = try parseString(buffer);
                    inline for (enum_t.fields) |field| {
                        if (std.mem.eql(u8, field.name, str)) {
                            return @enumFromInt(field.value);
                        }
                    }
                }

                unreachable;
            },
            else => {
                @compileError("Cannot deserialize type " ++ @typeName(T));
            },
        }
    }

    fn skipWhitespace(buffer: *[]const u8) void {
        while (buffer.*.len > 0 and std.ascii.isWhitespace(buffer.*[0])) {
            buffer.* = buffer.*[1..];
        }
    }
};

pub const JsonDef = struct {
    field_name: []const u8,
};

fn getJsonDef(comptime T: type, comptime field_name: []const u8) JsonDef {
    const TI = @typeInfo(T);

    std.debug.assert(TI == .@"struct");

    if (@hasDecl(T, "json_def")) {
        const json_defs = T.json_def;
        if (@hasField(@TypeOf(json_defs), field_name)) {
            return @field(T.json_def, field_name);
        }
    }

    return JsonDef{
        .field_name = field_name,
    };
}

test "writing" {
    const assert = std.debug.assert;

    // Struct
    {
        const val: struct {
            hello: u32,
            world: u32,
        } = .{
            .hello = 0x20,
            .world = 0x40,
        };

        var buf: [32]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);

        const size = try JsonWriter.write(val, fbs.writer());

        assert(std.mem.eql(u8, buf[0..size], "{\"hello\":\"0x20\",\"world\":\"0x40\"}"));
    }
}

test "reading" {
    const assert = std.debug.assert;
    const allocator = std.testing.allocator;

    // Struct
    {
        const Struct = struct {
            hello: u32,
            world: u32,
        };

        const buf = "{\"hello\":\"0x20\",\"world\":\"0x40\"}";

        var ptr: []const u8 = buf[0..];
        const result = try JsonReader.parse(allocator, &ptr, Struct);

        assert(result.hello == 0x20);
        assert(result.world == 0x40);
    }

    // Struct w/ optional
    {
        const Struct = struct {
            hello: u32,
            world: ?u32 = 0x60,
        };

        const buf = "{\"hello\":\"0x20\"}";

        var ptr: []const u8 = buf[0..];
        const result = try JsonReader.parse(allocator, &ptr, Struct);

        assert(result.hello == 0x20);
        assert(result.world == 0x60);
    }

    // Invalid number
    {
        const buf = "{";

        var ptr: []const u8 = buf[0..];
        const result = JsonReader.parse(allocator, &ptr, u32);
        try std.testing.expectError(error.UnexpectedCharacter, result);
    }

    // Unexpected EOF
    {
        const Struct = struct {
            hello: u32,
            world: u32,
        };

        const buf = "{\"hello";

        var ptr: []const u8 = buf[0..];
        const result = JsonReader.parse(allocator, &ptr, Struct);
        try std.testing.expectError(error.EndOfBuffer, result);
    }

    // Missing field
    {
        const Struct = struct {
            hello: u32,
            world: u32,
        };

        const buf = "{\"hello\":\"0x20\"}";

        var ptr: []const u8 = buf[0..];
        const result = JsonReader.parse(allocator, &ptr, Struct);
        try std.testing.expectError(error.MissingRequiredField, result);
    }
}

test "json def" {
    const json_def = getJsonDef(web3.abi.AbiEntry, "state_mutability");
    std.debug.assert(std.mem.eql(u8, json_def.field_name, "stateMutability"));
}
