package it.auties.leap.socket.platform.implementation;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.platform.SocketPlatform;
import it.auties.leap.socket.platform.ffi.unix.UnixKernel;
import it.auties.leap.socket.platform.ffi.unix.__Block_byref_ND;
import it.auties.leap.socket.platform.ffi.unix.dispatch_block_t;
import it.auties.leap.socket.platform.ffi.unix.dispatch_object_t;

import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import it.auties.leap.socket.SocketException;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

// GCD (General Central Dispatch)
public final class UnixPlatform extends SocketPlatform<Integer> {
    private static final UnixKernel.fcntl fcntl = UnixKernel.fcntl
            .makeInvoker(ValueLayout.JAVA_INT);
    private static final MemorySegment errno = Linker.nativeLinker()
            .defaultLookup()
            .findOrThrow("errno")
            .reinterpret(ValueLayout.JAVA_INT.byteSize());

    private MemorySegment gcdQueue;

    public UnixPlatform(SocketProtocol protocol) {
        super(protocol);
    }

    @Override
    protected Integer createHandle() {
        var socketHandle = UnixKernel.socket(UnixKernel.AF_INET(), UnixKernel.SOCK_STREAM(), 0);
        if (socketHandle == -1) {
            // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/socket.2.html
            throw new SocketException("Cannot create socket (socket call failed)");
        }

        var flags = fcntl.apply(socketHandle, UnixKernel.F_GETFL(), 0);
        if (flags == -1) {
            throw new SocketException("Cannot create socket (fcntl get call failed)");
        }

        var result = fcntl.apply(socketHandle, UnixKernel.F_SETFL(), flags | UnixKernel.O_NONBLOCK());
        if (result == -1) {
            throw new SocketException("Cannot create socket (fcntl set call failed)");
        }

        return socketHandle;
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        if (connected.getAndSet(true)) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: already connected"));
        }

        this.address = address;
        var remoteAddress = createRemoteAddress(address);
        if (remoteAddress.isEmpty()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName())));
        }

        var response = UnixKernel.connect(
                handle,
                remoteAddress.get(),
                (int) remoteAddress.get().byteSize()
        );
        if (response != -1) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket remote connection failure (async operation expected)"));
        }

        var errorCode = getErrorCode();
        if (errorCode != UnixKernel.EINPROGRESS() && errorCode != UnixKernel.ETIMEDOUT()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: remote connection failure (error code: %s)".formatted(errorCode)));
        }

        initIOBuffers();

        this.gcdQueue = UnixKernel.dispatch_queue_create(
                arena.allocateFrom("socket_" + handle),
                MemorySegment.NULL
        );
        return dispatch(DispatchEvent.WRITE).thenCompose(_ -> {
            var errorSegment = arena.allocate(ValueLayout.JAVA_INT);
            var result = UnixKernel.getsockopt(
                    handle,
                    UnixKernel.SOL_SOCKET(),
                    UnixKernel.SO_ERROR(),
                    errorSegment,
                    arena.allocateFrom(ValueLayout.JAVA_INT, (int) errorSegment.byteSize())
            );
            if (result < 0) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: cannot get result (error code: %s)".formatted(result)));
            }

            var error = errorSegment.get(ValueLayout.JAVA_INT, 0);
            if (error != 0) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: remote connection failure (error code: %s)".formatted(error)));
            }

            return CompletableFuture.completedFuture(null);
        });
    }

    @Override
    protected CompletableFuture<Void> writeUnchecked(ByteBuffer input) {
        var length = Math.min(input.remaining(), writeBufferSize);
        writeToIOBuffer(input, length);
        return dispatch(DispatchEvent.WRITE).thenCompose(_ -> {
            var result = UnixKernel.write(handle, writeBuffer, length);
            if (result == -1) {
                close();
                return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket closed)"));
            }

            if (input.hasRemaining()) {
                return writeUnchecked(input);
            }

            return CompletableFuture.completedFuture(null);
        });
    }

    @Override
    protected CompletableFuture<ByteBuffer> readUnchecked(ByteBuffer output) {
        return dispatch(DispatchEvent.READ).thenCompose(_ -> {
            var length = Math.min(output.remaining(), readBufferSize);
            var readLength = UnixKernel.read(handle, readBuffer, length);
            if (readLength <= 0) {
                close();
                return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socket closed)"));
            }

            readFromIOBuffer(output, Math.toIntExact(readLength));
            return CompletableFuture.completedFuture(output);
        });
    }

    @Override
    public void close() {
        if (!connected.get()) {
            return;
        }

        this.address = null;
        connected.set(false);
        UnixKernel.close(handle);
    }

    private int getErrorCode() {
        return (int) ValueLayout.JAVA_INT
                .varHandle()
                .getVolatile(errno, 0);
    }

    private CompletableFuture<Void> dispatch(DispatchEvent event) {
        var source = UnixKernel.dispatch_source_create(
                event.constant(),
                handle,
                0,
                gcdQueue
        );

        var future = new CompletableFuture<Void>();
        var handler = dispatch_block_t.allocate(() -> {
            if (!future.isDone()) {
                future.complete(null);
            }

            UnixKernel.dispatch_source_cancel(source);
        }, arena);

        var block = arena.allocate(__Block_byref_ND.layout());
        __Block_byref_ND.__isa(block, BlockType.GLOBAL.constant());
        __Block_byref_ND.__flags(block, UnixKernel.BLOCK_BYREF_LAYOUT_UNRETAINED());
        __Block_byref_ND.__reserved(block, 0);
        __Block_byref_ND.__FuncPtr(block, handler);
        UnixKernel.dispatch_source_set_event_handler(source, block);

        var obj = arena.allocate(dispatch_object_t.layout());
        dispatch_object_t._ds(obj, source);
        UnixKernel.dispatch_resume(obj);

        return future;
    }

    private enum DispatchEvent {
        READ("_dispatch_source_type_read"),
        WRITE("_dispatch_source_type_write");

        private final MemorySegment constant;

        DispatchEvent(String name) {
            this.constant = Linker.nativeLinker()
                    .defaultLookup()
                    .findOrThrow(name);
        }

        public MemorySegment constant() {
            return constant;
        }
    }

    private enum BlockType {
        GLOBAL("_NSConcreteGlobalBlock"),
        STACK("_NSConcreteStackBlock");

        private final MemorySegment constant;

        BlockType(String name) {
            this.constant = Linker.nativeLinker()
                    .defaultLookup()
                    .findOrThrow(name);
        }

        public MemorySegment constant() {
            return constant;
        }
    }
}
