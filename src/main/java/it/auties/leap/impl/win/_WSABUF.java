// Generated by jextract

package it.auties.leap.impl.win;

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
 * struct _WSABUF {
 *     ULONG len;
 *     CHAR *buf;
 * }
 * }
 */
public class _WSABUF {

    _WSABUF() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        WindowsSockets.C_LONG.withName("len"),
        MemoryLayout.paddingLayout(4),
        WindowsSockets.C_POINTER.withName("buf")
    ).withName("_WSABUF");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfInt len$LAYOUT = (OfInt)$LAYOUT.select(groupElement("len"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * ULONG len
     * }
     */
    public static final OfInt len$layout() {
        return len$LAYOUT;
    }

    private static final long len$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * ULONG len
     * }
     */
    public static final long len$offset() {
        return len$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * ULONG len
     * }
     */
    public static int len(MemorySegment struct) {
        return struct.get(len$LAYOUT, len$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * ULONG len
     * }
     */
    public static void len(MemorySegment struct, int fieldValue) {
        struct.set(len$LAYOUT, len$OFFSET, fieldValue);
    }

    private static final AddressLayout buf$LAYOUT = (AddressLayout)$LAYOUT.select(groupElement("buf"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * CHAR *buf
     * }
     */
    public static final AddressLayout buf$layout() {
        return buf$LAYOUT;
    }

    private static final long buf$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * CHAR *buf
     * }
     */
    public static final long buf$offset() {
        return buf$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * CHAR *buf
     * }
     */
    public static MemorySegment buf(MemorySegment struct) {
        return struct.get(buf$LAYOUT, buf$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * CHAR *buf
     * }
     */
    public static void buf(MemorySegment struct, MemorySegment fieldValue) {
        struct.set(buf$LAYOUT, buf$OFFSET, fieldValue);
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

