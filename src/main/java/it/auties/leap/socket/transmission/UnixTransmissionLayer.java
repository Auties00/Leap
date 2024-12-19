package it.auties.leap.socket.transmission;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.transmission.ffi.unix.UnixSockets;
import it.auties.leap.socket.transmission.ffi.unix.__Block_byref_ND;
import it.auties.leap.socket.transmission.ffi.unix.dispatch_block_t;
import it.auties.leap.socket.transmission.ffi.unix.dispatch_object_t;

import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

// GCD (General Central Dispatch)
final class UnixTransmissionLayer extends SocketTransmissionLayer<Integer> {
    private static final UnixSockets.fcntl fcntl = UnixSockets.fcntl
            .makeInvoker(ValueLayout.JAVA_INT);
    private static final MemorySegment errno = Linker.nativeLinker()
            .defaultLookup()
            .findOrThrow("errno")
            .reinterpret(ValueLayout.JAVA_INT.byteSize());

    private MemorySegment gcdQueue;

    UnixTransmissionLayer(SocketProtocol protocol) throws SocketException {
        super(protocol);
    }

    @Override
    Integer createHandle() throws SocketException {
        var socketHandle = UnixSockets.socket(UnixSockets.AF_INET(), UnixSockets.SOCK_STREAM(), 0);
        if (socketHandle == -1) {
            // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/socket.2.html
            throw new SocketException("Cannot create socket (socket call failed)");
        }

        var flags = fcntl.apply(socketHandle, UnixSockets.F_GETFL(), 0);
        if (flags == -1) {
            throw new SocketException("Cannot create socket (fcntl get call failed)");
        }

        var result = fcntl.apply(socketHandle, UnixSockets.F_SETFL(), flags | UnixSockets.O_NONBLOCK());
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

        var response = UnixSockets.connect(
                handle,
                remoteAddress.get(),
                (int) remoteAddress.get().byteSize()
        );
        if (response != -1) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket remote connection failure (async operation expected)"));
        }

        var errorCode = getErrorCode();
        if (errorCode != UnixSockets.EINPROGRESS() && errorCode != UnixSockets.ETIMEDOUT()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: remote connection failure (error code: %s)".formatted(errorCode)));
        }

        initIOBuffers();

        this.gcdQueue = UnixSockets.dispatch_queue_create(
                arena.allocateFrom("socket_" + handle),
                MemorySegment.NULL
        );
        return dispatch(DispatchEvent.WRITE).thenCompose(_ -> {
            var errorSegment = arena.allocate(ValueLayout.JAVA_INT);
            var result = UnixSockets.getsockopt(
                    handle,
                    UnixSockets.SOL_SOCKET(),
                    UnixSockets.SO_ERROR(),
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
            var result = UnixSockets.write(handle, writeBuffer, length);
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
            var readLength = UnixSockets.read(handle, readBuffer, length);
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
        UnixSockets.close(handle);
    }

    private int getErrorCode() {
        return (int) ValueLayout.JAVA_INT
                .varHandle()
                .getVolatile(errno, 0);
    }

    private CompletableFuture<Void> dispatch(DispatchEvent event) {
        var source = UnixSockets.dispatch_source_create(
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

            UnixSockets.dispatch_source_cancel(source);
        }, arena);

        var block = arena.allocate(__Block_byref_ND.layout());
        __Block_byref_ND.__isa(block, BlockType.GLOBAL.constant());
        __Block_byref_ND.__flags(block, UnixSockets.BLOCK_BYREF_LAYOUT_UNRETAINED());
        __Block_byref_ND.__reserved(block, 0);
        __Block_byref_ND.__FuncPtr(block, handler);
        UnixSockets.dispatch_source_set_event_handler(source, block);

        var obj = arena.allocate(dispatch_object_t.layout());
        dispatch_object_t._ds(obj, source);
        UnixSockets.dispatch_resume(obj);

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
