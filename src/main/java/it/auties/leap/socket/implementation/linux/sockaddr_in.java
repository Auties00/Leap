// Generated by jextract

package it.auties.leap.socket.implementation.linux;

import java.lang.foreign.*;
import java.lang.invoke.VarHandle;
import java.util.function.Consumer;

import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.MemoryLayout.PathElement.sequenceElement;
import static java.lang.foreign.ValueLayout.OfShort;

/**
 * {@snippet lang=c :
 * struct sockaddr_in {
 *     ADDRESS_FAMILY sin_family;
 *     USHORT sin_port;
 *     IN_ADDR sin_addr;
 *     CHAR sin_zero[8];
 * }
 * }
 */
public class sockaddr_in {

    sockaddr_in() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        LinuxKernel.C_SHORT.withName("sin_family"),
        LinuxKernel.C_SHORT.withName("sin_port"),
        in_addr.layout().withName("sin_addr"),
        MemoryLayout.sequenceLayout(8, LinuxKernel.C_CHAR).withName("sin_zero")
    ).withName("sockaddr_in");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfShort sin_family$LAYOUT = (OfShort)$LAYOUT.select(groupElement("sin_family"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * ADDRESS_FAMILY sin_family
     * }
     */
    public static final OfShort sin_family$layout() {
        return sin_family$LAYOUT;
    }

    private static final long sin_family$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * ADDRESS_FAMILY sin_family
     * }
     */
    public static final long sin_family$offset() {
        return sin_family$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * ADDRESS_FAMILY sin_family
     * }
     */
    public static short sin_family(MemorySegment struct) {
        return struct.get(sin_family$LAYOUT, sin_family$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * ADDRESS_FAMILY sin_family
     * }
     */
    public static void sin_family(MemorySegment struct, short fieldValue) {
        struct.set(sin_family$LAYOUT, sin_family$OFFSET, fieldValue);
    }

    private static final OfShort sin_port$LAYOUT = (OfShort)$LAYOUT.select(groupElement("sin_port"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * USHORT sin_port
     * }
     */
    public static final OfShort sin_port$layout() {
        return sin_port$LAYOUT;
    }

    private static final long sin_port$OFFSET = 2;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * USHORT sin_port
     * }
     */
    public static final long sin_port$offset() {
        return sin_port$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * USHORT sin_port
     * }
     */
    public static short sin_port(MemorySegment struct) {
        return struct.get(sin_port$LAYOUT, sin_port$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * USHORT sin_port
     * }
     */
    public static void sin_port(MemorySegment struct, short fieldValue) {
        struct.set(sin_port$LAYOUT, sin_port$OFFSET, fieldValue);
    }

    private static final GroupLayout sin_addr$LAYOUT = (GroupLayout)$LAYOUT.select(groupElement("sin_addr"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * IN_ADDR sin_addr
     * }
     */
    public static final GroupLayout sin_addr$layout() {
        return sin_addr$LAYOUT;
    }

    private static final long sin_addr$OFFSET = 4;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * IN_ADDR sin_addr
     * }
     */
    public static final long sin_addr$offset() {
        return sin_addr$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * IN_ADDR sin_addr
     * }
     */
    public static MemorySegment sin_addr(MemorySegment struct) {
        return struct.asSlice(sin_addr$OFFSET, sin_addr$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * IN_ADDR sin_addr
     * }
     */
    public static void sin_addr(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, sin_addr$OFFSET, sin_addr$LAYOUT.byteSize());
    }

    private static final SequenceLayout sin_zero$LAYOUT = (SequenceLayout)$LAYOUT.select(groupElement("sin_zero"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * CHAR sin_zero[8]
     * }
     */
    public static final SequenceLayout sin_zero$layout() {
        return sin_zero$LAYOUT;
    }

    private static final long sin_zero$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * CHAR sin_zero[8]
     * }
     */
    public static final long sin_zero$offset() {
        return sin_zero$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * CHAR sin_zero[8]
     * }
     */
    public static MemorySegment sin_zero(MemorySegment struct) {
        return struct.asSlice(sin_zero$OFFSET, sin_zero$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * CHAR sin_zero[8]
     * }
     */
    public static void sin_zero(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, sin_zero$OFFSET, sin_zero$LAYOUT.byteSize());
    }

    private static long[] sin_zero$DIMS = { 8 };

    /**
     * Dimensions for array field:
     * {@snippet lang=c :
     * CHAR sin_zero[8]
     * }
     */
    public static long[] sin_zero$dimensions() {
        return sin_zero$DIMS;
    }
    private static final VarHandle sin_zero$ELEM_HANDLE = sin_zero$LAYOUT.varHandle(sequenceElement());

    /**
     * Indexed getter for field:
     * {@snippet lang=c :
     * CHAR sin_zero[8]
     * }
     */
    public static byte sin_zero(MemorySegment struct, long index0) {
        return (byte)sin_zero$ELEM_HANDLE.get(struct, 0L, index0);
    }

    /**
     * Indexed setter for field:
     * {@snippet lang=c :
     * CHAR sin_zero[8]
     * }
     */
    public static void sin_zero(MemorySegment struct, long index0, byte fieldValue) {
        sin_zero$ELEM_HANDLE.set(struct, 0L, index0, fieldValue);
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

