const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const Allocator = std.mem.Allocator;

/// This allocator is similar to the std ArenaAllocator except the allocation list
/// is separate from the data so it can be free'd independently.
/// It is optimized for the happy case of deinit not being required and the ownership
/// of memory transferring to the child allocator.
pub const ArenaAllocator = struct {
    child_allocator: Allocator,
    buffer_list: std.SinglyLinkedList(Allocation) = .{},

    const Allocation = struct {
        ptr: usize,
        size: usize,
        log2_buf_align: u8,
    };

    pub fn allocator(self: *ArenaAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    const BufNode = std.SinglyLinkedList(Allocation).Node;

    pub fn init(child_allocator: Allocator) ArenaAllocator {
        return ArenaAllocator{
            .child_allocator = child_allocator,
        };
    }

    pub fn deinit(self: *ArenaAllocator) void {
        var frees = std.AutoHashMap(usize, bool).init(self.child_allocator);
        defer frees.deinit();

        var it = self.buffer_list.first;
        while (it) |node| {
            // this has to occur before the free because the free frees node
            const next_it = node.next;
            defer it = next_it;
            defer self.child_allocator.destroy(node);

            if (frees.contains(node.data.ptr)) {
                continue;
            }

            // If we can't keep track of the frees, memory will be left in an undefined state, so panic is the only safe way out
            frees.put(node.data.ptr, true) catch @panic("Out of memory");

            // Already freed
            if (node.data.size == 0) {
                continue;
            }

            // Free the data
            const alloc_buf = @as([*]u8, @ptrFromInt(node.data.ptr))[0..node.data.size];
            self.child_allocator.rawFree(alloc_buf, node.data.log2_buf_align, @returnAddress());
        }

        self.buffer_list.first = null;
    }

    /// Frees the internal accounting of allocations
    /// After a call to this method, memory is no longer tracked by this allocator and needs to be
    /// freed via its child allocator
    pub fn freeList(self: ArenaAllocator) void {
        var it = self.buffer_list.first;
        while (it) |node| {
            // this has to occur before the free because the free frees node
            defer self.child_allocator.destroy(node);
            const next_it = node.next;
            defer it = next_it;
        }
    }

    inline fn pushNode(self: *ArenaAllocator, ptr: usize, log2_buf_align: u8, size: usize) !void {
        var node = try self.child_allocator.create(BufNode);
        node.* = BufNode{ .data = .{
            .ptr = ptr,
            .log2_buf_align = log2_buf_align,
            .size = size,
        } };
        self.buffer_list.prepend(node);
    }

    fn alloc(ctx: *anyopaque, len: usize, log2_ptr_align: u8, ret_addr: usize) ?[*]u8 {
        var self: *ArenaAllocator = @ptrCast(@alignCast(ctx));
        const result = self.child_allocator.rawAlloc(len, log2_ptr_align, ret_addr);
        if (result) |buf| {
            self.pushNode(@intFromPtr(buf), log2_ptr_align, len) catch @panic("Out of memory");
        }
        return result;
    }

    fn resize(ctx: *anyopaque, buf: []u8, log2_buf_align: u8, new_len: usize, ret_addr: usize) bool {
        var self: *ArenaAllocator = @ptrCast(@alignCast(ctx));
        const result = self.child_allocator.rawResize(buf, log2_buf_align, new_len, ret_addr);
        if (result) {
            self.pushNode(@intFromPtr(buf.ptr), log2_buf_align, new_len) catch @panic("Out of memory");
        }
        return result;
    }

    fn free(ctx: *anyopaque, buf: []u8, log2_buf_align: u8, ret_addr: usize) void {
        var self: *ArenaAllocator = @ptrCast(@alignCast(ctx));
        self.child_allocator.rawFree(buf, log2_buf_align, ret_addr);
        self.pushNode(@intFromPtr(buf.ptr), log2_buf_align, 0) catch @panic("Out of memory");
    }
};

test "arena allocator" {
    var arena = ArenaAllocator.init(std.testing.allocator);
    var allocator = arena.allocator();

    var a = try allocator.alloc(u8, 256);
    _ = a;
    var b = try allocator.alloc(u8, 256);
    var c = try allocator.alloc(u8, 256);
    _ = c;

    allocator.free(b);

    arena.deinit();
}
