// Generated by jextract

package it.auties.leap.socket.transmission.ffi.unix;

import java.lang.foreign.*;
import java.util.function.*;

import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * {@snippet lang=c :
 * union {
 *     struct _os_object_s * _Nonnull _os_obj;
 *     struct dispatch_object_s * _Nonnull _do;
 *     struct dispatch_queue_s * _Nonnull _dq;
 *     struct dispatch_queue_attr_s * _Nonnull _dqa;
 *     struct dispatch_group_s * _Nonnull _dg;
 *     struct dispatch_source_s * _Nonnull _ds;
 *     struct dispatch_channel_s * _Nonnull _dch;
 *     struct dispatch_mach_s * _Nonnull _dm;
 *     struct dispatch_mach_msg_s * _Nonnull _dmsg;
 *     struct dispatch_semaphore_s * _Nonnull _dsema;
 *     struct dispatch_data_s * _Nonnull _ddata;
 *     struct dispatch_io_s * _Nonnull _dchannel;
 * }
 * }
 */
public class dispatch_object_t {

    dispatch_object_t() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.unionLayout(
        UnixKernel.C_POINTER.withName("_os_obj"),
        UnixKernel.C_POINTER.withName("_do"),
        UnixKernel.C_POINTER.withName("_dq"),
        UnixKernel.C_POINTER.withName("_dqa"),
        UnixKernel.C_POINTER.withName("_dg"),
        UnixKernel.C_POINTER.withName("_ds"),
        UnixKernel.C_POINTER.withName("_dch"),
        UnixKernel.C_POINTER.withName("_dm"),
        UnixKernel.C_POINTER.withName("_dmsg"),
        UnixKernel.C_POINTER.withName("_dsema"),
        UnixKernel.C_POINTER.withName("_ddata"),
        UnixKernel.C_POINTER.withName("_dchannel")
    ).withName("$anon$126:9");

    /**
     * The layout of this union
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final AddressLayout _os_obj$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_os_obj"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct _os_object_s * _Nonnull _os_obj
     * }
     */
    public static final AddressLayout _os_obj$layout() {
        return _os_obj$LAYOUT;
    }

    private static final long _os_obj$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct _os_object_s * _Nonnull _os_obj
     * }
     */
    public static final long _os_obj$offset() {
        return _os_obj$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct _os_object_s * _Nonnull _os_obj
     * }
     */
    public static MemorySegment _os_obj(MemorySegment union) {
        return union.get(_os_obj$LAYOUT, _os_obj$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct _os_object_s * _Nonnull _os_obj
     * }
     */
    public static void _os_obj(MemorySegment union, MemorySegment fieldValue) {
        union.set(_os_obj$LAYOUT, _os_obj$OFFSET, fieldValue);
    }

    private static final AddressLayout _do$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_do"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_object_s * _Nonnull _do
     * }
     */
    public static final AddressLayout _do$layout() {
        return _do$LAYOUT;
    }

    private static final long _do$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_object_s * _Nonnull _do
     * }
     */
    public static final long _do$offset() {
        return _do$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_object_s * _Nonnull _do
     * }
     */
    public static MemorySegment _do(MemorySegment union) {
        return union.get(_do$LAYOUT, _do$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_object_s * _Nonnull _do
     * }
     */
    public static void _do(MemorySegment union, MemorySegment fieldValue) {
        union.set(_do$LAYOUT, _do$OFFSET, fieldValue);
    }

    private static final AddressLayout _dq$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_dq"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_queue_s * _Nonnull _dq
     * }
     */
    public static final AddressLayout _dq$layout() {
        return _dq$LAYOUT;
    }

    private static final long _dq$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_queue_s * _Nonnull _dq
     * }
     */
    public static final long _dq$offset() {
        return _dq$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_queue_s * _Nonnull _dq
     * }
     */
    public static MemorySegment _dq(MemorySegment union) {
        return union.get(_dq$LAYOUT, _dq$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_queue_s * _Nonnull _dq
     * }
     */
    public static void _dq(MemorySegment union, MemorySegment fieldValue) {
        union.set(_dq$LAYOUT, _dq$OFFSET, fieldValue);
    }

    private static final AddressLayout _dqa$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_dqa"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_queue_attr_s * _Nonnull _dqa
     * }
     */
    public static final AddressLayout _dqa$layout() {
        return _dqa$LAYOUT;
    }

    private static final long _dqa$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_queue_attr_s * _Nonnull _dqa
     * }
     */
    public static final long _dqa$offset() {
        return _dqa$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_queue_attr_s * _Nonnull _dqa
     * }
     */
    public static MemorySegment _dqa(MemorySegment union) {
        return union.get(_dqa$LAYOUT, _dqa$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_queue_attr_s * _Nonnull _dqa
     * }
     */
    public static void _dqa(MemorySegment union, MemorySegment fieldValue) {
        union.set(_dqa$LAYOUT, _dqa$OFFSET, fieldValue);
    }

    private static final AddressLayout _dg$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_dg"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_group_s * _Nonnull _dg
     * }
     */
    public static final AddressLayout _dg$layout() {
        return _dg$LAYOUT;
    }

    private static final long _dg$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_group_s * _Nonnull _dg
     * }
     */
    public static final long _dg$offset() {
        return _dg$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_group_s * _Nonnull _dg
     * }
     */
    public static MemorySegment _dg(MemorySegment union) {
        return union.get(_dg$LAYOUT, _dg$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_group_s * _Nonnull _dg
     * }
     */
    public static void _dg(MemorySegment union, MemorySegment fieldValue) {
        union.set(_dg$LAYOUT, _dg$OFFSET, fieldValue);
    }

    private static final AddressLayout _ds$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_ds"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_source_s * _Nonnull _ds
     * }
     */
    public static final AddressLayout _ds$layout() {
        return _ds$LAYOUT;
    }

    private static final long _ds$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_source_s * _Nonnull _ds
     * }
     */
    public static final long _ds$offset() {
        return _ds$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_source_s * _Nonnull _ds
     * }
     */
    public static MemorySegment _ds(MemorySegment union) {
        return union.get(_ds$LAYOUT, _ds$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_source_s * _Nonnull _ds
     * }
     */
    public static void _ds(MemorySegment union, MemorySegment fieldValue) {
        union.set(_ds$LAYOUT, _ds$OFFSET, fieldValue);
    }

    private static final AddressLayout _dch$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_dch"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_channel_s * _Nonnull _dch
     * }
     */
    public static final AddressLayout _dch$layout() {
        return _dch$LAYOUT;
    }

    private static final long _dch$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_channel_s * _Nonnull _dch
     * }
     */
    public static final long _dch$offset() {
        return _dch$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_channel_s * _Nonnull _dch
     * }
     */
    public static MemorySegment _dch(MemorySegment union) {
        return union.get(_dch$LAYOUT, _dch$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_channel_s * _Nonnull _dch
     * }
     */
    public static void _dch(MemorySegment union, MemorySegment fieldValue) {
        union.set(_dch$LAYOUT, _dch$OFFSET, fieldValue);
    }

    private static final AddressLayout _dm$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_dm"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_mach_s * _Nonnull _dm
     * }
     */
    public static final AddressLayout _dm$layout() {
        return _dm$LAYOUT;
    }

    private static final long _dm$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_mach_s * _Nonnull _dm
     * }
     */
    public static final long _dm$offset() {
        return _dm$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_mach_s * _Nonnull _dm
     * }
     */
    public static MemorySegment _dm(MemorySegment union) {
        return union.get(_dm$LAYOUT, _dm$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_mach_s * _Nonnull _dm
     * }
     */
    public static void _dm(MemorySegment union, MemorySegment fieldValue) {
        union.set(_dm$LAYOUT, _dm$OFFSET, fieldValue);
    }

    private static final AddressLayout _dmsg$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_dmsg"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_mach_msg_s * _Nonnull _dmsg
     * }
     */
    public static final AddressLayout _dmsg$layout() {
        return _dmsg$LAYOUT;
    }

    private static final long _dmsg$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_mach_msg_s * _Nonnull _dmsg
     * }
     */
    public static final long _dmsg$offset() {
        return _dmsg$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_mach_msg_s * _Nonnull _dmsg
     * }
     */
    public static MemorySegment _dmsg(MemorySegment union) {
        return union.get(_dmsg$LAYOUT, _dmsg$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_mach_msg_s * _Nonnull _dmsg
     * }
     */
    public static void _dmsg(MemorySegment union, MemorySegment fieldValue) {
        union.set(_dmsg$LAYOUT, _dmsg$OFFSET, fieldValue);
    }

    private static final AddressLayout _dsema$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_dsema"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_semaphore_s * _Nonnull _dsema
     * }
     */
    public static final AddressLayout _dsema$layout() {
        return _dsema$LAYOUT;
    }

    private static final long _dsema$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_semaphore_s * _Nonnull _dsema
     * }
     */
    public static final long _dsema$offset() {
        return _dsema$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_semaphore_s * _Nonnull _dsema
     * }
     */
    public static MemorySegment _dsema(MemorySegment union) {
        return union.get(_dsema$LAYOUT, _dsema$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_semaphore_s * _Nonnull _dsema
     * }
     */
    public static void _dsema(MemorySegment union, MemorySegment fieldValue) {
        union.set(_dsema$LAYOUT, _dsema$OFFSET, fieldValue);
    }

    private static final AddressLayout _ddata$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_ddata"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_data_s * _Nonnull _ddata
     * }
     */
    public static final AddressLayout _ddata$layout() {
        return _ddata$LAYOUT;
    }

    private static final long _ddata$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_data_s * _Nonnull _ddata
     * }
     */
    public static final long _ddata$offset() {
        return _ddata$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_data_s * _Nonnull _ddata
     * }
     */
    public static MemorySegment _ddata(MemorySegment union) {
        return union.get(_ddata$LAYOUT, _ddata$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_data_s * _Nonnull _ddata
     * }
     */
    public static void _ddata(MemorySegment union, MemorySegment fieldValue) {
        union.set(_ddata$LAYOUT, _ddata$OFFSET, fieldValue);
    }

    private static final AddressLayout _dchannel$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("_dchannel"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct dispatch_io_s * _Nonnull _dchannel
     * }
     */
    public static final AddressLayout _dchannel$layout() {
        return _dchannel$LAYOUT;
    }

    private static final long _dchannel$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct dispatch_io_s * _Nonnull _dchannel
     * }
     */
    public static final long _dchannel$offset() {
        return _dchannel$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct dispatch_io_s * _Nonnull _dchannel
     * }
     */
    public static MemorySegment _dchannel(MemorySegment union) {
        return union.get(_dchannel$LAYOUT, _dchannel$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct dispatch_io_s * _Nonnull _dchannel
     * }
     */
    public static void _dchannel(MemorySegment union, MemorySegment fieldValue) {
        union.set(_dchannel$LAYOUT, _dchannel$OFFSET, fieldValue);
    }

    /**
     * Obtains a slice of {@code arrayParam} which selects the array element at {@code index}.
     * The returned segment has address {@code arrayParam.address() + index * layout().byteSize()}
     */
    public static MemorySegment asSlice(MemorySegment array, long index) {
        return array.asSlice(layout().byteSize() * index);
    }

    /**
     * The size (in bytes) of this union
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

