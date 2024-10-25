// Generated by jextract

package it.auties.leap.socket.platform.unix;

import java.lang.invoke.*;
import java.lang.foreign.*;
import java.util.*;
import java.util.stream.*;

import static java.lang.foreign.ValueLayout.*;

public class UnixSockets {

    UnixSockets() {
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
    private static final int O_NONBLOCK = (int)4L;
    /**
     * {@snippet lang=c :
     * #define O_NONBLOCK 4
     * }
     */
    public static int O_NONBLOCK() {
        return O_NONBLOCK;
    }
    private static final int F_GETFL = (int)3L;
    /**
     * {@snippet lang=c :
     * #define F_GETFL 3
     * }
     */
    public static int F_GETFL() {
        return F_GETFL;
    }
    private static final int F_SETFL = (int)4L;
    /**
     * {@snippet lang=c :
     * #define F_SETFL 4
     * }
     */
    public static int F_SETFL() {
        return F_SETFL;
    }
    private static final int SOCK_STREAM = (int)1L;
    /**
     * {@snippet lang=c :
     * #define SOCK_STREAM 1
     * }
     */
    public static int SOCK_STREAM() {
        return SOCK_STREAM;
    }
    private static final int SO_ERROR = (int)4103L;
    /**
     * {@snippet lang=c :
     * #define SO_ERROR 4103
     * }
     */
    public static int SO_ERROR() {
        return SO_ERROR;
    }
    private static final int SOL_SOCKET = (int)65535L;
    /**
     * {@snippet lang=c :
     * #define SOL_SOCKET 65535
     * }
     */
    public static int SOL_SOCKET() {
        return SOL_SOCKET;
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
    private static final int EINPROGRESS = (int)36L;
    /**
     * {@snippet lang=c :
     * #define EINPROGRESS 36
     * }
     */
    public static int EINPROGRESS() {
        return EINPROGRESS;
    }
    private static final int ETIMEDOUT = (int)60L;
    /**
     * {@snippet lang=c :
     * #define ETIMEDOUT 60
     * }
     */
    public static int ETIMEDOUT() {
        return ETIMEDOUT;
    }

    /**
     * Variadic invoker class for:
     * {@snippet lang=c :
     * int fcntl(int, int, ...)
     * }
     */
    public static class fcntl {
        private static final FunctionDescriptor BASE_DESC = FunctionDescriptor.of(
                UnixSockets.C_INT,
                UnixSockets.C_INT,
                UnixSockets.C_INT
            );
        private static final MemorySegment ADDR = UnixSockets.findOrThrow("fcntl");

        private final MethodHandle handle;
        private final FunctionDescriptor descriptor;
        private final MethodHandle spreader;

        private fcntl(MethodHandle handle, FunctionDescriptor descriptor, MethodHandle spreader) {
            this.handle = handle;
            this.descriptor = descriptor;
            this.spreader = spreader;
        }

        /**
         * Variadic invoker factory for:
         * {@snippet lang=c :
         * int fcntl(int, int, ...)
         * }
         */
        public static fcntl makeInvoker(MemoryLayout... layouts) {
            FunctionDescriptor desc$ = BASE_DESC.appendArgumentLayouts(layouts);
            Linker.Option fva$ = Linker.Option.firstVariadicArg(BASE_DESC.argumentLayouts().size());
            var mh$ = Linker.nativeLinker().downcallHandle(ADDR, desc$, fva$);
            var spreader$ = mh$.asSpreader(Object[].class, layouts.length);
            return new fcntl(mh$, desc$, spreader$);
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

        public int apply(int x0, int x1, Object... x2) {
            try {
                if (TRACE_DOWNCALLS) {
                    traceDowncall("fcntl", x0, x1, x2);
                }
                return (int)spreader.invokeExact(x0, x1, x2);
            } catch(IllegalArgumentException | ClassCastException ex$)  {
                throw ex$; // rethrow IAE from passing wrong number/type of args
            } catch (Throwable ex$) {
               throw new AssertionError("should not reach here", ex$);
            }
        }
    }

    private static class close {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            UnixSockets.C_INT,
            UnixSockets.C_INT
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("close");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * int close(int)
     * }
     */
    public static FunctionDescriptor close$descriptor() {
        return close.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * int close(int)
     * }
     */
    public static MethodHandle close$handle() {
        return close.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * int close(int)
     * }
     */
    public static MemorySegment close$address() {
        return close.ADDR;
    }

    /**
     * {@snippet lang=c :
     * int close(int)
     * }
     */
    public static int close(int x0) {
        var mh$ = close.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("close", x0);
            }
            return (int)mh$.invokeExact(x0);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class read {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            UnixSockets.C_LONG,
            UnixSockets.C_INT,
            UnixSockets.C_POINTER,
            UnixSockets.C_LONG
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("read");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * ssize_t read(int, void *, size_t)
     * }
     */
    public static FunctionDescriptor read$descriptor() {
        return read.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * ssize_t read(int, void *, size_t)
     * }
     */
    public static MethodHandle read$handle() {
        return read.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * ssize_t read(int, void *, size_t)
     * }
     */
    public static MemorySegment read$address() {
        return read.ADDR;
    }

    /**
     * {@snippet lang=c :
     * ssize_t read(int, void *, size_t)
     * }
     */
    public static long read(int x0, MemorySegment x1, long x2) {
        var mh$ = read.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("read", x0, x1, x2);
            }
            return (long)mh$.invokeExact(x0, x1, x2);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class write {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            UnixSockets.C_LONG,
            UnixSockets.C_INT,
            UnixSockets.C_POINTER,
            UnixSockets.C_LONG
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("write");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * ssize_t write(int __fd, const void *__buf, size_t __nbyte)
     * }
     */
    public static FunctionDescriptor write$descriptor() {
        return write.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * ssize_t write(int __fd, const void *__buf, size_t __nbyte)
     * }
     */
    public static MethodHandle write$handle() {
        return write.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * ssize_t write(int __fd, const void *__buf, size_t __nbyte)
     * }
     */
    public static MemorySegment write$address() {
        return write.ADDR;
    }

    /**
     * {@snippet lang=c :
     * ssize_t write(int __fd, const void *__buf, size_t __nbyte)
     * }
     */
    public static long write(int __fd, MemorySegment __buf, long __nbyte) {
        var mh$ = write.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("write", __fd, __buf, __nbyte);
            }
            return (long)mh$.invokeExact(__fd, __buf, __nbyte);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class dispatch_resume {
        public static final FunctionDescriptor DESC = FunctionDescriptor.ofVoid(
            dispatch_object_t.layout()
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("dispatch_resume");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern void dispatch_resume(dispatch_object_t object)
     * }
     */
    public static FunctionDescriptor dispatch_resume$descriptor() {
        return dispatch_resume.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern void dispatch_resume(dispatch_object_t object)
     * }
     */
    public static MethodHandle dispatch_resume$handle() {
        return dispatch_resume.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern void dispatch_resume(dispatch_object_t object)
     * }
     */
    public static MemorySegment dispatch_resume$address() {
        return dispatch_resume.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern void dispatch_resume(dispatch_object_t object)
     * }
     */
    public static void dispatch_resume(MemorySegment object) {
        var mh$ = dispatch_resume.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("dispatch_resume", object);
            }
            mh$.invokeExact(object);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class dispatch_queue_create {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            UnixSockets.C_POINTER,
            UnixSockets.C_POINTER,
            UnixSockets.C_POINTER
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("dispatch_queue_create");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern dispatch_queue_t  _Nonnull dispatch_queue_create(const char * _Nullable label, dispatch_queue_attr_t  _Nullable attr)
     * }
     */
    public static FunctionDescriptor dispatch_queue_create$descriptor() {
        return dispatch_queue_create.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern dispatch_queue_t  _Nonnull dispatch_queue_create(const char * _Nullable label, dispatch_queue_attr_t  _Nullable attr)
     * }
     */
    public static MethodHandle dispatch_queue_create$handle() {
        return dispatch_queue_create.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern dispatch_queue_t  _Nonnull dispatch_queue_create(const char * _Nullable label, dispatch_queue_attr_t  _Nullable attr)
     * }
     */
    public static MemorySegment dispatch_queue_create$address() {
        return dispatch_queue_create.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern dispatch_queue_t  _Nonnull dispatch_queue_create(const char * _Nullable label, dispatch_queue_attr_t  _Nullable attr)
     * }
     */
    public static MemorySegment dispatch_queue_create(MemorySegment label, MemorySegment attr) {
        var mh$ = dispatch_queue_create.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("dispatch_queue_create", label, attr);
            }
            return (MemorySegment)mh$.invokeExact(label, attr);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class dispatch_source_create {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            UnixSockets.C_POINTER,
            UnixSockets.C_POINTER,
            UnixSockets.C_LONG,
            UnixSockets.C_LONG,
            UnixSockets.C_POINTER
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("dispatch_source_create");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern dispatch_source_t  _Nonnull dispatch_source_create(dispatch_source_type_t  _Nonnull type, uintptr_t handle, uintptr_t mask, dispatch_queue_t  _Nullable queue)
     * }
     */
    public static FunctionDescriptor dispatch_source_create$descriptor() {
        return dispatch_source_create.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern dispatch_source_t  _Nonnull dispatch_source_create(dispatch_source_type_t  _Nonnull type, uintptr_t handle, uintptr_t mask, dispatch_queue_t  _Nullable queue)
     * }
     */
    public static MethodHandle dispatch_source_create$handle() {
        return dispatch_source_create.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern dispatch_source_t  _Nonnull dispatch_source_create(dispatch_source_type_t  _Nonnull type, uintptr_t handle, uintptr_t mask, dispatch_queue_t  _Nullable queue)
     * }
     */
    public static MemorySegment dispatch_source_create$address() {
        return dispatch_source_create.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern dispatch_source_t  _Nonnull dispatch_source_create(dispatch_source_type_t  _Nonnull type, uintptr_t handle, uintptr_t mask, dispatch_queue_t  _Nullable queue)
     * }
     */
    public static MemorySegment dispatch_source_create(MemorySegment type, long handle, long mask, MemorySegment queue) {
        var mh$ = dispatch_source_create.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("dispatch_source_create", type, handle, mask, queue);
            }
            return (MemorySegment)mh$.invokeExact(type, handle, mask, queue);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class dispatch_source_set_event_handler {
        public static final FunctionDescriptor DESC = FunctionDescriptor.ofVoid(
            UnixSockets.C_POINTER,
            UnixSockets.C_POINTER
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("dispatch_source_set_event_handler");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern void dispatch_source_set_event_handler(dispatch_source_t  _Nonnull source, dispatch_block_t  _Nullable handler)
     * }
     */
    public static FunctionDescriptor dispatch_source_set_event_handler$descriptor() {
        return dispatch_source_set_event_handler.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern void dispatch_source_set_event_handler(dispatch_source_t  _Nonnull source, dispatch_block_t  _Nullable handler)
     * }
     */
    public static MethodHandle dispatch_source_set_event_handler$handle() {
        return dispatch_source_set_event_handler.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern void dispatch_source_set_event_handler(dispatch_source_t  _Nonnull source, dispatch_block_t  _Nullable handler)
     * }
     */
    public static MemorySegment dispatch_source_set_event_handler$address() {
        return dispatch_source_set_event_handler.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern void dispatch_source_set_event_handler(dispatch_source_t  _Nonnull source, dispatch_block_t  _Nullable handler)
     * }
     */
    public static void dispatch_source_set_event_handler(MemorySegment source, MemorySegment handler) {
        var mh$ = dispatch_source_set_event_handler.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("dispatch_source_set_event_handler", source, handler);
            }
            mh$.invokeExact(source, handler);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class dispatch_source_cancel {
        public static final FunctionDescriptor DESC = FunctionDescriptor.ofVoid(
            UnixSockets.C_POINTER
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("dispatch_source_cancel");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern void dispatch_source_cancel(dispatch_source_t  _Nonnull source)
     * }
     */
    public static FunctionDescriptor dispatch_source_cancel$descriptor() {
        return dispatch_source_cancel.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern void dispatch_source_cancel(dispatch_source_t  _Nonnull source)
     * }
     */
    public static MethodHandle dispatch_source_cancel$handle() {
        return dispatch_source_cancel.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern void dispatch_source_cancel(dispatch_source_t  _Nonnull source)
     * }
     */
    public static MemorySegment dispatch_source_cancel$address() {
        return dispatch_source_cancel.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern void dispatch_source_cancel(dispatch_source_t  _Nonnull source)
     * }
     */
    public static void dispatch_source_cancel(MemorySegment source) {
        var mh$ = dispatch_source_cancel.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("dispatch_source_cancel", source);
            }
            mh$.invokeExact(source);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class connect {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            UnixSockets.C_INT,
            UnixSockets.C_INT,
            UnixSockets.C_POINTER,
            UnixSockets.C_INT
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("connect");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * int connect(int, const struct sockaddr *, socklen_t)
     * }
     */
    public static FunctionDescriptor connect$descriptor() {
        return connect.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * int connect(int, const struct sockaddr *, socklen_t)
     * }
     */
    public static MethodHandle connect$handle() {
        return connect.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * int connect(int, const struct sockaddr *, socklen_t)
     * }
     */
    public static MemorySegment connect$address() {
        return connect.ADDR;
    }

    /**
     * {@snippet lang=c :
     * int connect(int, const struct sockaddr *, socklen_t)
     * }
     */
    public static int connect(int x0, MemorySegment x1, int x2) {
        var mh$ = connect.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("connect", x0, x1, x2);
            }
            return (int)mh$.invokeExact(x0, x1, x2);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class getsockopt {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            UnixSockets.C_INT,
            UnixSockets.C_INT,
            UnixSockets.C_INT,
            UnixSockets.C_INT,
            UnixSockets.C_POINTER,
            UnixSockets.C_POINTER
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("getsockopt");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * int getsockopt(int, int, int, void *restrict, socklen_t *restrict)
     * }
     */
    public static FunctionDescriptor getsockopt$descriptor() {
        return getsockopt.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * int getsockopt(int, int, int, void *restrict, socklen_t *restrict)
     * }
     */
    public static MethodHandle getsockopt$handle() {
        return getsockopt.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * int getsockopt(int, int, int, void *restrict, socklen_t *restrict)
     * }
     */
    public static MemorySegment getsockopt$address() {
        return getsockopt.ADDR;
    }

    /**
     * {@snippet lang=c :
     * int getsockopt(int, int, int, void *restrict, socklen_t *restrict)
     * }
     */
    public static int getsockopt(int x0, int x1, int x2, MemorySegment x3, MemorySegment x4) {
        var mh$ = getsockopt.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("getsockopt", x0, x1, x2, x3, x4);
            }
            return (int)mh$.invokeExact(x0, x1, x2, x3, x4);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class socket {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            UnixSockets.C_INT,
            UnixSockets.C_INT,
            UnixSockets.C_INT,
            UnixSockets.C_INT
        );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("socket");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * int socket(int, int, int)
     * }
     */
    public static FunctionDescriptor socket$descriptor() {
        return socket.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * int socket(int, int, int)
     * }
     */
    public static MethodHandle socket$handle() {
        return socket.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * int socket(int, int, int)
     * }
     */
    public static MemorySegment socket$address() {
        return socket.ADDR;
    }

    /**
     * {@snippet lang=c :
     * int socket(int, int, int)
     * }
     */
    public static int socket(int x0, int x1, int x2) {
        var mh$ = socket.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("socket", x0, x1, x2);
            }
            return (int)mh$.invokeExact(x0, x1, x2);
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }

    private static class __error {
        public static final FunctionDescriptor DESC = FunctionDescriptor.of(
            UnixSockets.C_POINTER    );

        public static final MemorySegment ADDR = UnixSockets.findOrThrow("__error");

        public static final MethodHandle HANDLE = Linker.nativeLinker().downcallHandle(ADDR, DESC);
    }

    /**
     * Function descriptor for:
     * {@snippet lang=c :
     * extern int *__error()
     * }
     */
    public static FunctionDescriptor __error$descriptor() {
        return __error.DESC;
    }

    /**
     * Downcall method handle for:
     * {@snippet lang=c :
     * extern int *__error()
     * }
     */
    public static MethodHandle __error$handle() {
        return __error.HANDLE;
    }

    /**
     * Address for:
     * {@snippet lang=c :
     * extern int *__error()
     * }
     */
    public static MemorySegment __error$address() {
        return __error.ADDR;
    }

    /**
     * {@snippet lang=c :
     * extern int *__error()
     * }
     */
    public static MemorySegment __error() {
        var mh$ = __error.HANDLE;
        try {
            if (TRACE_DOWNCALLS) {
                traceDowncall("__error");
            }
            return (MemorySegment)mh$.invokeExact();
        } catch (Throwable ex$) {
           throw new AssertionError("should not reach here", ex$);
        }
    }
    private static final int BLOCK_BYREF_LAYOUT_UNRETAINED = (int)1342177280L;
    /**
     * {@snippet lang=c :
     * enum BlockByrefFlags.BLOCK_BYREF_LAYOUT_UNRETAINED = 1342177280
     * }
     */
    public static int BLOCK_BYREF_LAYOUT_UNRETAINED() {
        return BLOCK_BYREF_LAYOUT_UNRETAINED;
    }
}

