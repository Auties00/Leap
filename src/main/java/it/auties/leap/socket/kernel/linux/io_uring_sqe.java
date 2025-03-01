// Generated by jextract

package it.auties.leap.socket.kernel.linux;

import java.lang.invoke.*;
import java.lang.foreign.*;
import java.nio.ByteOrder;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

import static java.lang.foreign.ValueLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * {@snippet lang=c :
 * struct io_uring_sqe {
 *     __u8 opcode;
 *     __u8 flags;
 *     __u16 ioprio;
 *     __s32 fd;
 *     union {
 *         __u64 off;
 *         __u64 addr2;
 *     };
 *     union {
 *         __u64 addr;
 *         __u64 splice_off_in;
 *     };
 *     __u32 len;
 *     union {
 *         __kernel_rwf_t rw_flags;
 *         __u32 fsync_flags;
 *         __u16 poll_events;
 *         __u32 poll32_events;
 *         __u32 sync_range_flags;
 *         __u32 msg_flags;
 *         __u32 timeout_flags;
 *         __u32 accept_flags;
 *         __u32 cancel_flags;
 *         __u32 open_flags;
 *         __u32 statx_flags;
 *         __u32 fadvise_advice;
 *         __u32 splice_flags;
 *         __u32 rename_flags;
 *         __u32 unlink_flags;
 *         __u32 hardlink_flags;
 *     };
 *     __u64 user_data;
 *     union {
 *         __u16 buf_index;
 *         __u16 buf_group;
 *     };
 *     __u16 personality;
 *     union {
 *         __s32 splice_fd_in;
 *         __u32 file_index;
 *     };
 *     __u64 __pad2[2];
 * }
 * }
 */
public class io_uring_sqe {

    io_uring_sqe() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        LinuxKernel.C_CHAR.withName("opcode"),
        LinuxKernel.C_CHAR.withName("flags"),
        LinuxKernel.C_SHORT.withName("ioprio"),
        LinuxKernel.C_INT.withName("fd"),
        MemoryLayout.unionLayout(
            LinuxKernel.C_LONG_LONG.withName("off"),
            LinuxKernel.C_LONG_LONG.withName("addr2")
        ).withName("$anon$22:2"),
        MemoryLayout.unionLayout(
            LinuxKernel.C_LONG_LONG.withName("addr"),
            LinuxKernel.C_LONG_LONG.withName("splice_off_in")
        ).withName("$anon$26:2"),
        LinuxKernel.C_INT.withName("len"),
        MemoryLayout.unionLayout(
            LinuxKernel.C_INT.withName("rw_flags"),
            LinuxKernel.C_INT.withName("fsync_flags"),
            LinuxKernel.C_SHORT.withName("poll_events"),
            LinuxKernel.C_INT.withName("poll32_events"),
            LinuxKernel.C_INT.withName("sync_range_flags"),
            LinuxKernel.C_INT.withName("msg_flags"),
            LinuxKernel.C_INT.withName("timeout_flags"),
            LinuxKernel.C_INT.withName("accept_flags"),
            LinuxKernel.C_INT.withName("cancel_flags"),
            LinuxKernel.C_INT.withName("open_flags"),
            LinuxKernel.C_INT.withName("statx_flags"),
            LinuxKernel.C_INT.withName("fadvise_advice"),
            LinuxKernel.C_INT.withName("splice_flags"),
            LinuxKernel.C_INT.withName("rename_flags"),
            LinuxKernel.C_INT.withName("unlink_flags"),
            LinuxKernel.C_INT.withName("hardlink_flags")
        ).withName("$anon$31:2"),
        LinuxKernel.C_LONG_LONG.withName("user_data"),
        MemoryLayout.unionLayout(
            LinuxKernel.align(LinuxKernel.C_SHORT, 1).withName("buf_index"),
            LinuxKernel.align(LinuxKernel.C_SHORT, 1).withName("buf_group")
        ).withName("$anon$51:2"),
        LinuxKernel.C_SHORT.withName("personality"),
        MemoryLayout.unionLayout(
            LinuxKernel.C_INT.withName("splice_fd_in"),
            LinuxKernel.C_INT.withName("file_index")
        ).withName("$anon$59:2"),
        MemoryLayout.sequenceLayout(2, LinuxKernel.C_LONG_LONG).withName("__pad2")
    ).withName("io_uring_sqe");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfByte opcode$LAYOUT = (OfByte)$LAYOUT.select(groupElement("opcode"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u8 opcode
     * }
     */
    public static final OfByte opcode$layout() {
        return opcode$LAYOUT;
    }

    private static final long opcode$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u8 opcode
     * }
     */
    public static final long opcode$offset() {
        return opcode$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u8 opcode
     * }
     */
    public static byte opcode(MemorySegment struct) {
        return struct.get(opcode$LAYOUT, opcode$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u8 opcode
     * }
     */
    public static void opcode(MemorySegment struct, byte fieldValue) {
        struct.set(opcode$LAYOUT, opcode$OFFSET, fieldValue);
    }

    private static final OfByte flags$LAYOUT = (OfByte)$LAYOUT.select(groupElement("flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u8 flags
     * }
     */
    public static final OfByte flags$layout() {
        return flags$LAYOUT;
    }

    private static final long flags$OFFSET = 1;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u8 flags
     * }
     */
    public static final long flags$offset() {
        return flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u8 flags
     * }
     */
    public static byte flags(MemorySegment struct) {
        return struct.get(flags$LAYOUT, flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u8 flags
     * }
     */
    public static void flags(MemorySegment struct, byte fieldValue) {
        struct.set(flags$LAYOUT, flags$OFFSET, fieldValue);
    }

    private static final OfShort ioprio$LAYOUT = (OfShort)$LAYOUT.select(groupElement("ioprio"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u16 ioprio
     * }
     */
    public static final OfShort ioprio$layout() {
        return ioprio$LAYOUT;
    }

    private static final long ioprio$OFFSET = 2;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u16 ioprio
     * }
     */
    public static final long ioprio$offset() {
        return ioprio$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u16 ioprio
     * }
     */
    public static short ioprio(MemorySegment struct) {
        return struct.get(ioprio$LAYOUT, ioprio$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u16 ioprio
     * }
     */
    public static void ioprio(MemorySegment struct, short fieldValue) {
        struct.set(ioprio$LAYOUT, ioprio$OFFSET, fieldValue);
    }

    private static final OfInt fd$LAYOUT = (OfInt)$LAYOUT.select(groupElement("fd"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __s32 fd
     * }
     */
    public static final OfInt fd$layout() {
        return fd$LAYOUT;
    }

    private static final long fd$OFFSET = 4;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __s32 fd
     * }
     */
    public static final long fd$offset() {
        return fd$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __s32 fd
     * }
     */
    public static int fd(MemorySegment struct) {
        return struct.get(fd$LAYOUT, fd$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __s32 fd
     * }
     */
    public static void fd(MemorySegment struct, int fieldValue) {
        struct.set(fd$LAYOUT, fd$OFFSET, fieldValue);
    }

    private static final OfLong off$LAYOUT = (OfLong)$LAYOUT.select(groupElement("$anon$22:2"), groupElement("off"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u64 off
     * }
     */
    public static final OfLong off$layout() {
        return off$LAYOUT;
    }

    private static final long off$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u64 off
     * }
     */
    public static final long off$offset() {
        return off$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u64 off
     * }
     */
    public static long off(MemorySegment struct) {
        return struct.get(off$LAYOUT, off$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u64 off
     * }
     */
    public static void off(MemorySegment struct, long fieldValue) {
        struct.set(off$LAYOUT, off$OFFSET, fieldValue);
    }

    private static final OfLong addr2$LAYOUT = (OfLong)$LAYOUT.select(groupElement("$anon$22:2"), groupElement("addr2"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u64 addr2
     * }
     */
    public static final OfLong addr2$layout() {
        return addr2$LAYOUT;
    }

    private static final long addr2$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u64 addr2
     * }
     */
    public static final long addr2$offset() {
        return addr2$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u64 addr2
     * }
     */
    public static long addr2(MemorySegment struct) {
        return struct.get(addr2$LAYOUT, addr2$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u64 addr2
     * }
     */
    public static void addr2(MemorySegment struct, long fieldValue) {
        struct.set(addr2$LAYOUT, addr2$OFFSET, fieldValue);
    }

    private static final OfLong addr$LAYOUT = (OfLong)$LAYOUT.select(groupElement("$anon$26:2"), groupElement("addr"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u64 addr
     * }
     */
    public static final OfLong addr$layout() {
        return addr$LAYOUT;
    }

    private static final long addr$OFFSET = 16;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u64 addr
     * }
     */
    public static final long addr$offset() {
        return addr$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u64 addr
     * }
     */
    public static long addr(MemorySegment struct) {
        return struct.get(addr$LAYOUT, addr$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u64 addr
     * }
     */
    public static void addr(MemorySegment struct, long fieldValue) {
        struct.set(addr$LAYOUT, addr$OFFSET, fieldValue);
    }

    private static final OfLong splice_off_in$LAYOUT = (OfLong)$LAYOUT.select(groupElement("$anon$26:2"), groupElement("splice_off_in"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u64 splice_off_in
     * }
     */
    public static final OfLong splice_off_in$layout() {
        return splice_off_in$LAYOUT;
    }

    private static final long splice_off_in$OFFSET = 16;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u64 splice_off_in
     * }
     */
    public static final long splice_off_in$offset() {
        return splice_off_in$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u64 splice_off_in
     * }
     */
    public static long splice_off_in(MemorySegment struct) {
        return struct.get(splice_off_in$LAYOUT, splice_off_in$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u64 splice_off_in
     * }
     */
    public static void splice_off_in(MemorySegment struct, long fieldValue) {
        struct.set(splice_off_in$LAYOUT, splice_off_in$OFFSET, fieldValue);
    }

    private static final OfInt len$LAYOUT = (OfInt)$LAYOUT.select(groupElement("len"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 len
     * }
     */
    public static final OfInt len$layout() {
        return len$LAYOUT;
    }

    private static final long len$OFFSET = 24;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 len
     * }
     */
    public static final long len$offset() {
        return len$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 len
     * }
     */
    public static int len(MemorySegment struct) {
        return struct.get(len$LAYOUT, len$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 len
     * }
     */
    public static void len(MemorySegment struct, int fieldValue) {
        struct.set(len$LAYOUT, len$OFFSET, fieldValue);
    }

    private static final OfInt rw_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("rw_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __kernel_rwf_t rw_flags
     * }
     */
    public static final OfInt rw_flags$layout() {
        return rw_flags$LAYOUT;
    }

    private static final long rw_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __kernel_rwf_t rw_flags
     * }
     */
    public static final long rw_flags$offset() {
        return rw_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __kernel_rwf_t rw_flags
     * }
     */
    public static int rw_flags(MemorySegment struct) {
        return struct.get(rw_flags$LAYOUT, rw_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __kernel_rwf_t rw_flags
     * }
     */
    public static void rw_flags(MemorySegment struct, int fieldValue) {
        struct.set(rw_flags$LAYOUT, rw_flags$OFFSET, fieldValue);
    }

    private static final OfInt fsync_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("fsync_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 fsync_flags
     * }
     */
    public static final OfInt fsync_flags$layout() {
        return fsync_flags$LAYOUT;
    }

    private static final long fsync_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 fsync_flags
     * }
     */
    public static final long fsync_flags$offset() {
        return fsync_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 fsync_flags
     * }
     */
    public static int fsync_flags(MemorySegment struct) {
        return struct.get(fsync_flags$LAYOUT, fsync_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 fsync_flags
     * }
     */
    public static void fsync_flags(MemorySegment struct, int fieldValue) {
        struct.set(fsync_flags$LAYOUT, fsync_flags$OFFSET, fieldValue);
    }

    private static final OfShort poll_events$LAYOUT = (OfShort)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("poll_events"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u16 poll_events
     * }
     */
    public static final OfShort poll_events$layout() {
        return poll_events$LAYOUT;
    }

    private static final long poll_events$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u16 poll_events
     * }
     */
    public static final long poll_events$offset() {
        return poll_events$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u16 poll_events
     * }
     */
    public static short poll_events(MemorySegment struct) {
        return struct.get(poll_events$LAYOUT, poll_events$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u16 poll_events
     * }
     */
    public static void poll_events(MemorySegment struct, short fieldValue) {
        struct.set(poll_events$LAYOUT, poll_events$OFFSET, fieldValue);
    }

    private static final OfInt poll32_events$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("poll32_events"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 poll32_events
     * }
     */
    public static final OfInt poll32_events$layout() {
        return poll32_events$LAYOUT;
    }

    private static final long poll32_events$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 poll32_events
     * }
     */
    public static final long poll32_events$offset() {
        return poll32_events$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 poll32_events
     * }
     */
    public static int poll32_events(MemorySegment struct) {
        return struct.get(poll32_events$LAYOUT, poll32_events$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 poll32_events
     * }
     */
    public static void poll32_events(MemorySegment struct, int fieldValue) {
        struct.set(poll32_events$LAYOUT, poll32_events$OFFSET, fieldValue);
    }

    private static final OfInt sync_range_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("sync_range_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 sync_range_flags
     * }
     */
    public static final OfInt sync_range_flags$layout() {
        return sync_range_flags$LAYOUT;
    }

    private static final long sync_range_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 sync_range_flags
     * }
     */
    public static final long sync_range_flags$offset() {
        return sync_range_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 sync_range_flags
     * }
     */
    public static int sync_range_flags(MemorySegment struct) {
        return struct.get(sync_range_flags$LAYOUT, sync_range_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 sync_range_flags
     * }
     */
    public static void sync_range_flags(MemorySegment struct, int fieldValue) {
        struct.set(sync_range_flags$LAYOUT, sync_range_flags$OFFSET, fieldValue);
    }

    private static final OfInt msg_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("msg_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 msg_flags
     * }
     */
    public static final OfInt msg_flags$layout() {
        return msg_flags$LAYOUT;
    }

    private static final long msg_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 msg_flags
     * }
     */
    public static final long msg_flags$offset() {
        return msg_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 msg_flags
     * }
     */
    public static int msg_flags(MemorySegment struct) {
        return struct.get(msg_flags$LAYOUT, msg_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 msg_flags
     * }
     */
    public static void msg_flags(MemorySegment struct, int fieldValue) {
        struct.set(msg_flags$LAYOUT, msg_flags$OFFSET, fieldValue);
    }

    private static final OfInt timeout_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("timeout_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 timeout_flags
     * }
     */
    public static final OfInt timeout_flags$layout() {
        return timeout_flags$LAYOUT;
    }

    private static final long timeout_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 timeout_flags
     * }
     */
    public static final long timeout_flags$offset() {
        return timeout_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 timeout_flags
     * }
     */
    public static int timeout_flags(MemorySegment struct) {
        return struct.get(timeout_flags$LAYOUT, timeout_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 timeout_flags
     * }
     */
    public static void timeout_flags(MemorySegment struct, int fieldValue) {
        struct.set(timeout_flags$LAYOUT, timeout_flags$OFFSET, fieldValue);
    }

    private static final OfInt accept_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("accept_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 accept_flags
     * }
     */
    public static final OfInt accept_flags$layout() {
        return accept_flags$LAYOUT;
    }

    private static final long accept_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 accept_flags
     * }
     */
    public static final long accept_flags$offset() {
        return accept_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 accept_flags
     * }
     */
    public static int accept_flags(MemorySegment struct) {
        return struct.get(accept_flags$LAYOUT, accept_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 accept_flags
     * }
     */
    public static void accept_flags(MemorySegment struct, int fieldValue) {
        struct.set(accept_flags$LAYOUT, accept_flags$OFFSET, fieldValue);
    }

    private static final OfInt cancel_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("cancel_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 cancel_flags
     * }
     */
    public static final OfInt cancel_flags$layout() {
        return cancel_flags$LAYOUT;
    }

    private static final long cancel_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 cancel_flags
     * }
     */
    public static final long cancel_flags$offset() {
        return cancel_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 cancel_flags
     * }
     */
    public static int cancel_flags(MemorySegment struct) {
        return struct.get(cancel_flags$LAYOUT, cancel_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 cancel_flags
     * }
     */
    public static void cancel_flags(MemorySegment struct, int fieldValue) {
        struct.set(cancel_flags$LAYOUT, cancel_flags$OFFSET, fieldValue);
    }

    private static final OfInt open_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("open_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 open_flags
     * }
     */
    public static final OfInt open_flags$layout() {
        return open_flags$LAYOUT;
    }

    private static final long open_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 open_flags
     * }
     */
    public static final long open_flags$offset() {
        return open_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 open_flags
     * }
     */
    public static int open_flags(MemorySegment struct) {
        return struct.get(open_flags$LAYOUT, open_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 open_flags
     * }
     */
    public static void open_flags(MemorySegment struct, int fieldValue) {
        struct.set(open_flags$LAYOUT, open_flags$OFFSET, fieldValue);
    }

    private static final OfInt statx_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("statx_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 statx_flags
     * }
     */
    public static final OfInt statx_flags$layout() {
        return statx_flags$LAYOUT;
    }

    private static final long statx_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 statx_flags
     * }
     */
    public static final long statx_flags$offset() {
        return statx_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 statx_flags
     * }
     */
    public static int statx_flags(MemorySegment struct) {
        return struct.get(statx_flags$LAYOUT, statx_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 statx_flags
     * }
     */
    public static void statx_flags(MemorySegment struct, int fieldValue) {
        struct.set(statx_flags$LAYOUT, statx_flags$OFFSET, fieldValue);
    }

    private static final OfInt fadvise_advice$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("fadvise_advice"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 fadvise_advice
     * }
     */
    public static final OfInt fadvise_advice$layout() {
        return fadvise_advice$LAYOUT;
    }

    private static final long fadvise_advice$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 fadvise_advice
     * }
     */
    public static final long fadvise_advice$offset() {
        return fadvise_advice$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 fadvise_advice
     * }
     */
    public static int fadvise_advice(MemorySegment struct) {
        return struct.get(fadvise_advice$LAYOUT, fadvise_advice$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 fadvise_advice
     * }
     */
    public static void fadvise_advice(MemorySegment struct, int fieldValue) {
        struct.set(fadvise_advice$LAYOUT, fadvise_advice$OFFSET, fieldValue);
    }

    private static final OfInt splice_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("splice_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 splice_flags
     * }
     */
    public static final OfInt splice_flags$layout() {
        return splice_flags$LAYOUT;
    }

    private static final long splice_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 splice_flags
     * }
     */
    public static final long splice_flags$offset() {
        return splice_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 splice_flags
     * }
     */
    public static int splice_flags(MemorySegment struct) {
        return struct.get(splice_flags$LAYOUT, splice_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 splice_flags
     * }
     */
    public static void splice_flags(MemorySegment struct, int fieldValue) {
        struct.set(splice_flags$LAYOUT, splice_flags$OFFSET, fieldValue);
    }

    private static final OfInt rename_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("rename_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 rename_flags
     * }
     */
    public static final OfInt rename_flags$layout() {
        return rename_flags$LAYOUT;
    }

    private static final long rename_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 rename_flags
     * }
     */
    public static final long rename_flags$offset() {
        return rename_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 rename_flags
     * }
     */
    public static int rename_flags(MemorySegment struct) {
        return struct.get(rename_flags$LAYOUT, rename_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 rename_flags
     * }
     */
    public static void rename_flags(MemorySegment struct, int fieldValue) {
        struct.set(rename_flags$LAYOUT, rename_flags$OFFSET, fieldValue);
    }

    private static final OfInt unlink_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("unlink_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 unlink_flags
     * }
     */
    public static final OfInt unlink_flags$layout() {
        return unlink_flags$LAYOUT;
    }

    private static final long unlink_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 unlink_flags
     * }
     */
    public static final long unlink_flags$offset() {
        return unlink_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 unlink_flags
     * }
     */
    public static int unlink_flags(MemorySegment struct) {
        return struct.get(unlink_flags$LAYOUT, unlink_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 unlink_flags
     * }
     */
    public static void unlink_flags(MemorySegment struct, int fieldValue) {
        struct.set(unlink_flags$LAYOUT, unlink_flags$OFFSET, fieldValue);
    }

    private static final OfInt hardlink_flags$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$31:2"), groupElement("hardlink_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 hardlink_flags
     * }
     */
    public static final OfInt hardlink_flags$layout() {
        return hardlink_flags$LAYOUT;
    }

    private static final long hardlink_flags$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 hardlink_flags
     * }
     */
    public static final long hardlink_flags$offset() {
        return hardlink_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 hardlink_flags
     * }
     */
    public static int hardlink_flags(MemorySegment struct) {
        return struct.get(hardlink_flags$LAYOUT, hardlink_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 hardlink_flags
     * }
     */
    public static void hardlink_flags(MemorySegment struct, int fieldValue) {
        struct.set(hardlink_flags$LAYOUT, hardlink_flags$OFFSET, fieldValue);
    }

    private static final OfLong user_data$LAYOUT = (OfLong)$LAYOUT.select(groupElement("user_data"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u64 user_data
     * }
     */
    public static final OfLong user_data$layout() {
        return user_data$LAYOUT;
    }

    private static final long user_data$OFFSET = 32;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u64 user_data
     * }
     */
    public static final long user_data$offset() {
        return user_data$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u64 user_data
     * }
     */
    public static long user_data(MemorySegment struct) {
        return struct.get(user_data$LAYOUT, user_data$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u64 user_data
     * }
     */
    public static void user_data(MemorySegment struct, long fieldValue) {
        struct.set(user_data$LAYOUT, user_data$OFFSET, fieldValue);
    }

    private static final OfShort buf_index$LAYOUT = (OfShort)$LAYOUT.select(groupElement("$anon$51:2"), groupElement("buf_index"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u16 buf_index
     * }
     */
    public static final OfShort buf_index$layout() {
        return buf_index$LAYOUT;
    }

    private static final long buf_index$OFFSET = 40;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u16 buf_index
     * }
     */
    public static final long buf_index$offset() {
        return buf_index$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u16 buf_index
     * }
     */
    public static short buf_index(MemorySegment struct) {
        return struct.get(buf_index$LAYOUT, buf_index$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u16 buf_index
     * }
     */
    public static void buf_index(MemorySegment struct, short fieldValue) {
        struct.set(buf_index$LAYOUT, buf_index$OFFSET, fieldValue);
    }

    private static final OfShort buf_group$LAYOUT = (OfShort)$LAYOUT.select(groupElement("$anon$51:2"), groupElement("buf_group"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u16 buf_group
     * }
     */
    public static final OfShort buf_group$layout() {
        return buf_group$LAYOUT;
    }

    private static final long buf_group$OFFSET = 40;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u16 buf_group
     * }
     */
    public static final long buf_group$offset() {
        return buf_group$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u16 buf_group
     * }
     */
    public static short buf_group(MemorySegment struct) {
        return struct.get(buf_group$LAYOUT, buf_group$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u16 buf_group
     * }
     */
    public static void buf_group(MemorySegment struct, short fieldValue) {
        struct.set(buf_group$LAYOUT, buf_group$OFFSET, fieldValue);
    }

    private static final OfShort personality$LAYOUT = (OfShort)$LAYOUT.select(groupElement("personality"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u16 personality
     * }
     */
    public static final OfShort personality$layout() {
        return personality$LAYOUT;
    }

    private static final long personality$OFFSET = 42;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u16 personality
     * }
     */
    public static final long personality$offset() {
        return personality$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u16 personality
     * }
     */
    public static short personality(MemorySegment struct) {
        return struct.get(personality$LAYOUT, personality$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u16 personality
     * }
     */
    public static void personality(MemorySegment struct, short fieldValue) {
        struct.set(personality$LAYOUT, personality$OFFSET, fieldValue);
    }

    private static final OfInt splice_fd_in$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$59:2"), groupElement("splice_fd_in"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __s32 splice_fd_in
     * }
     */
    public static final OfInt splice_fd_in$layout() {
        return splice_fd_in$LAYOUT;
    }

    private static final long splice_fd_in$OFFSET = 44;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __s32 splice_fd_in
     * }
     */
    public static final long splice_fd_in$offset() {
        return splice_fd_in$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __s32 splice_fd_in
     * }
     */
    public static int splice_fd_in(MemorySegment struct) {
        return struct.get(splice_fd_in$LAYOUT, splice_fd_in$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __s32 splice_fd_in
     * }
     */
    public static void splice_fd_in(MemorySegment struct, int fieldValue) {
        struct.set(splice_fd_in$LAYOUT, splice_fd_in$OFFSET, fieldValue);
    }

    private static final OfInt file_index$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$59:2"), groupElement("file_index"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u32 file_index
     * }
     */
    public static final OfInt file_index$layout() {
        return file_index$LAYOUT;
    }

    private static final long file_index$OFFSET = 44;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u32 file_index
     * }
     */
    public static final long file_index$offset() {
        return file_index$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u32 file_index
     * }
     */
    public static int file_index(MemorySegment struct) {
        return struct.get(file_index$LAYOUT, file_index$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u32 file_index
     * }
     */
    public static void file_index(MemorySegment struct, int fieldValue) {
        struct.set(file_index$LAYOUT, file_index$OFFSET, fieldValue);
    }

    private static final SequenceLayout __pad2$LAYOUT = (SequenceLayout)$LAYOUT.select(groupElement("__pad2"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __u64 __pad2[2]
     * }
     */
    public static final SequenceLayout __pad2$layout() {
        return __pad2$LAYOUT;
    }

    private static final long __pad2$OFFSET = 48;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __u64 __pad2[2]
     * }
     */
    public static final long __pad2$offset() {
        return __pad2$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __u64 __pad2[2]
     * }
     */
    public static MemorySegment __pad2(MemorySegment struct) {
        return struct.asSlice(__pad2$OFFSET, __pad2$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __u64 __pad2[2]
     * }
     */
    public static void __pad2(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, __pad2$OFFSET, __pad2$LAYOUT.byteSize());
    }

    private static long[] __pad2$DIMS = { 2 };

    /**
     * Dimensions for array field:
     * {@snippet lang=c :
     * __u64 __pad2[2]
     * }
     */
    public static long[] __pad2$dimensions() {
        return __pad2$DIMS;
    }
    private static final VarHandle __pad2$ELEM_HANDLE = __pad2$LAYOUT.varHandle(sequenceElement());

    /**
     * Indexed getter for field:
     * {@snippet lang=c :
     * __u64 __pad2[2]
     * }
     */
    public static long __pad2(MemorySegment struct, long index0) {
        return (long)__pad2$ELEM_HANDLE.get(struct, 0L, index0);
    }

    /**
     * Indexed setter for field:
     * {@snippet lang=c :
     * __u64 __pad2[2]
     * }
     */
    public static void __pad2(MemorySegment struct, long index0, long fieldValue) {
        __pad2$ELEM_HANDLE.set(struct, 0L, index0, fieldValue);
    }

    /**
     * Obtains a slice of {@code arrayParam} which selects the array element at {@code index}.
     * The returned segment has address {@code arrayParam.address() + index * layout().byteSize()}
     */
    public static MemorySegment asSlice(MemorySegment array, long index) {
        return array.asSlice(layout().byteSize() * index);
    }

    /**
     * The size (in bytes) of this struct
     */
    public static long sizeof() { return layout().byteSize(); }

    /**
     * Allocate a segment of size {@code layout().byteSize()} using {@code allocator}
     */
    public static MemorySegment allocate(SegmentAllocator allocator) {
        return allocator.allocate(layout());
    }

    /**
     * Allocate an array of size {@code elementCount} using {@code allocator}.
     * The returned segment has size {@code elementCount * layout().byteSize()}.
     */
    public static MemorySegment allocateArray(long elementCount, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(elementCount, layout()));
    }

    /**
     * Reinterprets {@code addr} using target {@code arena} and {@code cleanupAction} (if any).
     * The returned segment has size {@code layout().byteSize()}
     */
    public static MemorySegment reinterpret(MemorySegment addr, Arena arena, Consumer<MemorySegment> cleanup) {
        return reinterpret(addr, 1, arena, cleanup);
    }

    /**
     * Reinterprets {@code addr} using target {@code arena} and {@code cleanupAction} (if any).
     * The returned segment has size {@code elementCount * layout().byteSize()}
     */
    public static MemorySegment reinterpret(MemorySegment addr, long elementCount, Arena arena, Consumer<MemorySegment> cleanup) {
        return addr.reinterpret(layout().byteSize() * elementCount, arena, cleanup);
    }
}

