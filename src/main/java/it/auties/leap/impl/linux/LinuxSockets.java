// Generated by jextract

package it.auties.leap.impl.linux;

import java.lang.invoke.*;
import java.lang.foreign.*;
import java.nio.ByteOrder;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

import static java.lang.foreign.ValueLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

public class LinuxSockets {

    LinuxSockets() {
        // Should not be called directly
    }

    static final Arena LIBRARY_ARENA = Arena.ofAuto();
    static final boolean TRACE_DOWNCALLS = Boolean.getBoolean("jextract.trace.downcalls");

    static void traceDowncall(String name, Object... args) {
         String traceArgs = Arrays.stream(args)
                       .map(Object::toString)
                       .collect(Collectors.joining(", "));
         System.out.printf("%s(%s)\n", name, traceArgs);
    }

    static MemorySegment findOrThrow(String symbol) {
        return SYMBOL_LOOKUP.find(symbol)
            .orElseThrow(() -> new UnsatisfiedLinkError("unresolved symbol: " + symbol));
    }

    static MethodHandle upcallHandle(Class<?> fi, String name, FunctionDescriptor fdesc) {
        try {
            return MethodHandles.lookup().findVirtual(fi, name, fdesc.toMethodType());
        } catch (ReflectiveOperationException ex) {
            throw new AssertionError(ex);
        }
    }

    static MemoryLayout align(MemoryLayout layout, long align) {
        return switch (layout) {
            case PaddingLayout p -> p;
            case ValueLayout v -> v.withByteAlignment(align);
            case GroupLayout g -> {
                MemoryLayout[] alignedMembers = g.memberLayouts().stream()
                        .map(m -> align(m, align)).toArray(MemoryLayout[]::new);
                yield g instanceof StructLayout ?
                        MemoryLayout.structLayout(alignedMembers) : MemoryLayout.unionLayout(alignedMembers);
            }
            case SequenceLayout s -> MemoryLayout.sequenceLayout(s.elementCount(), align(s.elementLayout(), align));
        };
    }

    static final SymbolLookup SYMBOL_LOOKUP = SymbolLookup.loaderLookup()
            .or(Linker.nativeLinker().defaultLookup());

    public static final ValueLayout.OfBoolean C_BOOL = ValueLayout.JAVA_BOOLEAN;
    public static final ValueLayout.OfByte C_CHAR = ValueLayout.JAVA_BYTE;
    public static final ValueLayout.OfShort C_SHORT = ValueLayout.JAVA_SHORT;
    public static final ValueLayout.OfInt C_INT = ValueLayout.JAVA_INT;
    public static final ValueLayout.OfLong C_LONG_LONG = ValueLayout.JAVA_LONG;
    public static final ValueLayout.OfFloat C_FLOAT = ValueLayout.JAVA_FLOAT;
    public static final ValueLayout.OfDouble C_DOUBLE = ValueLayout.JAVA_DOUBLE;
    public static final AddressLayout C_POINTER = ValueLayout.ADDRESS
            .withTargetLayout(MemoryLayout.sequenceLayout(java.lang.Long.MAX_VALUE, JAVA_BYTE));
    public static final ValueLayout.OfLong C_LONG = ValueLayout.JAVA_LONG;
    private static final int __NR_io_uring_setup = (int)425L;
    /**
     * {@snippet lang=c :
     * #define __NR_io_uring_setup 425
     * }
     */
    public static int __NR_io_uring_setup() {
        return __NR_io_uring_setup;
    }
    private static final int __NR_io_uring_enter = (int)426L;
    /**
     * {@snippet lang=c :
     * #define __NR_io_uring_enter 426
     * }
     */
    public static int __NR_io_uring_enter() {
        return __NR_io_uring_enter;
    }
    private static final int MAP_POPULATE = (int)32768L;
    /**
     * {@snippet lang=c :
     * #define MAP_POPULATE 32768
     * }
     */
    public static int MAP_POPULATE() {
        return MAP_POPULATE;
    }
    private static final int PROT_READ = (int)1L;
    /**
     * {@snippet lang=c :
     * #define PROT_READ 1
     * }
     */
    public static int PROT_READ() {
        return PROT_READ;
    }
    private static final int PROT_WRITE = (int)2L;
    /**
     * {@snippet lang=c :
     * #define PROT_WRITE 2
     * }
     */
    public static int PROT_WRITE() {
        return PROT_WRITE;
    }
    private static final int MAP_SHARED = (int)1L;
    /**
     * {@snippet lang=c :
     * #define MAP_SHARED 1
     * }
     */
    public static int MAP_SHARED() {
        return MAP_SHARED;
    }

    private static class close {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            LinuxSockets.C_INT,
            LinuxSockets.C_INT
        );

        public static final MemorySegment ADDR = LinuxSockets.findOrThrow("close");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern int close(int __fd)
     * }
     */
    public static FunctionDescriptor close$descriptor() {
        return close.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern int close(int __fd)
     * }
     */
    public static MethodHandle close$handle() {
        return close.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern int close(int __fd)
     * }
     */
    public static MemorySegment close$address() {
        return close.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern int close(int __fd)
     * }
     */
    public static int close(int __fd) {
        var mh$ = close.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("close", __fd);
            }
            return (int)mh$.invokeExact(__fd);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    /**
     * Variadic invoker class for:
     * {@snippet lang=c :
     * extern long syscall(long __sysno, ...)
     * }
     */
    public static class syscall {
        private static final FunctionDescriptor BASE_DESC = FunctionDescriptor.of(
                LinuxSockets.C_LONG,
                LinuxSockets.C_LONG
            );
        private static final MemorySegment ADDR = LinuxSockets.findOrThrow("syscall");

        private final MethodHandle handle;
        private final FunctionDescriptor descriptor;
        private final MethodHandle spreader;

        private syscall(MethodHandle handle, FunctionDescriptor descriptor, MethodHandle spreader) {
            this.handle = handle;
            this.descriptor = descriptor;
            this.spreader = spreader;
        }

        /**
         * Variadic invoker factory for:
         * {@snippet lang=c :
         * extern long syscall(long __sysno, ...)
         * }
         */
        public static syscall makeInvoker(MemoryLayout... layouts) {
            FunctionDescriptor desc$ = BASE_DESC.appendArgumentLayouts(layouts);
            Linker.Option fva$ = Linker.Option.firstVariadicArg(BASE_DESC.argumentLayouts().size());
            var mh$ = Linker.nativeLinker().downcallHandle(ADDR, desc$, fva$);
            var spreader$ = mh$.asSpreader(Object[].class, layouts.length);
            return new syscall(mh$, desc$, spreader$);
        }

        /**
         * {@return the address}
         */
        public static MemorySegment address() {
            return ADDR;
        }

        /**
         * {@return the specialized method handle}
         */
        public MethodHandle handle() {
            return handle;
        }

        /**
         * {@return the specialized descriptor}
         */
        public FunctionDescriptor descriptor() {
            return descriptor;
        }

        public long apply(long __sysno, Object... x1) {
            try {
                if (TRACE_DOWNCALLS) {
                    traceDowncall("syscall", __sysno, x1);
                }
                return (long)spreader.invokeExact(__sysno, x1);
            } catch(IllegalArgumentException | ClassCastException ex$)  {
                throw ex$; // rethrow IAE from passing wrong number/type of args
            } catch (Throwable ex$) {
               throw new AssertionError("should not reach here", ex$);
            }
        }
    }
    private static final int SOCK_STREAM = (int)1L;
    /**
     * {@snippet lang=c :
     * enum __socket_type.SOCK_STREAM = 1
     * }
     */
    public static int SOCK_STREAM() {
        return SOCK_STREAM;
    }
    private static final int SOCK_NONBLOCK = (int)2048L;
    /**
     * {@snippet lang=c :
     * enum __socket_type.SOCK_NONBLOCK = 2048
     * }
     */
    public static int SOCK_NONBLOCK() {
        return SOCK_NONBLOCK;
    }
    private static final int SHUT_RDWR = (int)2L;
    /**
     * {@snippet lang=c :
     * enum <anonymous>.SHUT_RDWR = 2
     * }
     */
    public static int SHUT_RDWR() {
        return SHUT_RDWR;
    }

    private static class socket {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            LinuxSockets.C_INT,
            LinuxSockets.C_INT,
            LinuxSockets.C_INT,
            LinuxSockets.C_INT
        );

        public static final MemorySegment ADDR = LinuxSockets.findOrThrow("socket");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern int socket(int __domain, int __type, int __protocol)
     * }
     */
    public static FunctionDescriptor socket$descriptor() {
        return socket.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern int socket(int __domain, int __type, int __protocol)
     * }
     */
    public static MethodHandle socket$handle() {
        return socket.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern int socket(int __domain, int __type, int __protocol)
     * }
     */
    public static MemorySegment socket$address() {
        return socket.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern int socket(int __domain, int __type, int __protocol)
     * }
     */
    public static int socket(int __domain, int __type, int __protocol) {
        var mh$ = socket.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("socket", __domain, __type, __protocol);
            }
            return (int)mh$.invokeExact(__domain, __type, __protocol);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class shutdown {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            LinuxSockets.C_INT,
            LinuxSockets.C_INT,
            LinuxSockets.C_INT
        );

        public static final MemorySegment ADDR = LinuxSockets.findOrThrow("shutdown");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern int shutdown(int __fd, int __how)
     * }
     */
    public static FunctionDescriptor shutdown$descriptor() {
        return shutdown.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern int shutdown(int __fd, int __how)
     * }
     */
    public static MethodHandle shutdown$handle() {
        return shutdown.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern int shutdown(int __fd, int __how)
     * }
     */
    public static MemorySegment shutdown$address() {
        return shutdown.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern int shutdown(int __fd, int __how)
     * }
     */
    public static int shutdown(int __fd, int __how) {
        var mh$ = shutdown.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("shutdown", __fd, __how);
            }
            return (int)mh$.invokeExact(__fd, __how);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }
    private static final int IORING_OP_WRITEV = (int)2L;
    /**
     * {@snippet lang=c :
     * enum <anonymous>.IORING_OP_WRITEV = 2
     * }
     */
    public static int IORING_OP_WRITEV() {
        return IORING_OP_WRITEV;
    }
    private static final int IORING_OP_CONNECT = (int)16L;
    /**
     * {@snippet lang=c :
     * enum <anonymous>.IORING_OP_CONNECT = 16
     * }
     */
    public static int IORING_OP_CONNECT() {
        return IORING_OP_CONNECT;
    }
    private static final int IORING_OP_READ = (int)22L;
    /**
     * {@snippet lang=c :
     * enum <anonymous>.IORING_OP_READ = 22
     * }
     */
    public static int IORING_OP_READ() {
        return IORING_OP_READ;
    }
    private static final int IORING_OP_WRITE = (int)23L;
    /**
     * {@snippet lang=c :
     * enum <anonymous>.IORING_OP_WRITE = 23
     * }
     */
    public static int IORING_OP_WRITE() {
        return IORING_OP_WRITE;
    }
    private static final int IORING_OP_SEND = (int)26L;
    /**
     * {@snippet lang=c :
     * enum <anonymous>.IORING_OP_SEND = 26
     * }
     */
    public static int IORING_OP_SEND() {
        return IORING_OP_SEND;
    }
    private static final int IORING_OP_RECV = (int)27L;
    /**
     * {@snippet lang=c :
     * enum <anonymous>.IORING_OP_RECV = 27
     * }
     */
    public static int IORING_OP_RECV() {
        return IORING_OP_RECV;
    }

    private static class mmap {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            LinuxSockets.C_POINTER,
            LinuxSockets.C_POINTER,
            LinuxSockets.C_LONG,
            LinuxSockets.C_INT,
            LinuxSockets.C_INT,
            LinuxSockets.C_INT,
            LinuxSockets.C_LONG
        );

        public static final MemorySegment ADDR = LinuxSockets.findOrThrow("mmap");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern void *mmap(void *__addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset)
     * }
     */
    public static FunctionDescriptor mmap$descriptor() {
        return mmap.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern void *mmap(void *__addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset)
     * }
     */
    public static MethodHandle mmap$handle() {
        return mmap.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern void *mmap(void *__addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset)
     * }
     */
    public static MemorySegment mmap$address() {
        return mmap.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern void *mmap(void *__addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset)
     * }
     */
    public static MemorySegment mmap(MemorySegment __addr, long __len, int __prot, int __flags, int __fd, long __offset) {
        var mh$ = mmap.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("mmap", __addr, __len, __prot, __flags, __fd, __offset);
            }
            return (MemorySegment)mh$.invokeExact(__addr, __len, __prot, __flags, __fd, __offset);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }
    private static final int AF_INET = (int)2L;
    /**
     * {@snippet lang=c :
     * #define AF_INET 2
     * }
     */
    public static int AF_INET() {
        return AF_INET;
    }
    private static final long IORING_OFF_SQ_RING = 0L;
    /**
     * {@snippet lang=c :
     * #define IORING_OFF_SQ_RING 0
     * }
     */
    public static long IORING_OFF_SQ_RING() {
        return IORING_OFF_SQ_RING;
    }
    private static final long IORING_OFF_CQ_RING = 134217728L;
    /**
     * {@snippet lang=c :
     * #define IORING_OFF_CQ_RING 134217728
     * }
     */
    public static long IORING_OFF_CQ_RING() {
        return IORING_OFF_CQ_RING;
    }
    private static final long IORING_OFF_SQES = 268435456L;
    /**
     * {@snippet lang=c :
     * #define IORING_OFF_SQES 268435456
     * }
     */
    public static long IORING_OFF_SQES() {
        return IORING_OFF_SQES;
    }
    private static final int IORING_ENTER_GETEVENTS = (int)1L;
    /**
     * {@snippet lang=c :
     * #define IORING_ENTER_GETEVENTS 1
     * }
     */
    public static int IORING_ENTER_GETEVENTS() {
        return IORING_ENTER_GETEVENTS;
    }
    private static final int IORING_FEAT_SINGLE_MMAP = (int)1L;
    /**
     * {@snippet lang=c :
     * #define IORING_FEAT_SINGLE_MMAP 1
     * }
     */
    public static int IORING_FEAT_SINGLE_MMAP() {
        return IORING_FEAT_SINGLE_MMAP;
    }
    private static final MemorySegment MAP_FAILED = MemorySegment.ofAddress(-1L);
    /**
     * {@snippet lang=c :
     * #define MAP_FAILED (void*) -1
     * }
     */
    public static MemorySegment MAP_FAILED() {
        return MAP_FAILED;
    }
}
