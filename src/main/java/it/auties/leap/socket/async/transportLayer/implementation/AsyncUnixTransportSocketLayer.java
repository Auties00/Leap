package it.auties.leap.socket.async.transportLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayerFactory;
import it.auties.leap.socket.kernel.unix.*;
import it.auties.leap.socket.kernel.win.sockaddr_in;

import java.lang.foreign.Arena;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

// GCD (General Central Dispatch)
public final class AsyncUnixTransportSocketLayer extends AsyncNativeTransportSocketLayer<Integer> {
    private static final AsyncSocketTransportLayerFactory FACTORY = AsyncUnixTransportSocketLayer::new;

    public static AsyncSocketTransportLayerFactory factory() {
        return FACTORY;
    }

    private static final UnixKernel.fcntl fcntl = UnixKernel.fcntl
            .makeInvoker(ValueLayout.JAVA_INT);
    private static final MemorySegment errno = Linker.nativeLinker()
            .defaultLookup()
            .findOrThrow("errno")
            .reinterpret(ValueLayout.JAVA_INT.byteSize());

    private GCD dispatcher;

    public AsyncUnixTransportSocketLayer(SocketProtocol protocol) {
        super(protocol);
    }

    @Override
    protected Integer createNativeHandle() {
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
    public CompletableFuture<Void> connectNative(InetSocketAddress address) {
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

        this.dispatcher = new GCD(handle);
        return dispatcher.dispatch(GCD.DispatchEvent.WRITE).thenCompose(_ -> {
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

            connected.set(true);
            return NO_RESULT;
        });
    }

    private Optional<MemorySegment> createRemoteAddress(InetSocketAddress address) {
        var remoteAddress = arena.allocate(sockaddr_in.layout());
        sockaddr_in.sin_family(remoteAddress, (short) UnixKernel.AF_INET());
        sockaddr_in.sin_port(remoteAddress, Short.reverseBytes((short) address.getPort()));
        var inAddr = arena.allocate(in_addr.layout());
        var ipv4Host = getLittleEndianIPV4Host(address);
        if (ipv4Host.isEmpty()) {
            return Optional.empty();
        }

        in_addr.S_un(inAddr, arena.allocateFrom(UnixKernel.C_INT, ipv4Host.getAsInt()));
        sockaddr_in.sin_addr(remoteAddress, inAddr);
        return Optional.of(remoteAddress);
    }

    @Override
    protected CompletableFuture<Void> writeNative(ByteBuffer input) {
        var length = Math.min(input.remaining(), writeBufferSize);
        writeToIOBuffer(input, length);
        return dispatcher.dispatch(GCD.DispatchEvent.WRITE).thenCompose(_ -> {
            var result = UnixKernel.write(handle, writeBuffer, length);
            if (result == -1) {
                close();
                return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket closed)"));
            }

            if (input.hasRemaining()) {
                return writeNative(input);
            }

            return NO_RESULT;
        });
    }

    @Override
    protected CompletableFuture<Void> readNative(ByteBuffer output, boolean lastRead) {
        return dispatcher.dispatch(GCD.DispatchEvent.READ).thenCompose(_ -> {
            var length = Math.min(output.remaining(), readBufferSize);
            var readLength = UnixKernel.read(handle, readBuffer, length);
            if (readLength <= 0) {
                close();
                return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socket closed)"));
            }

            readFromIOBuffer(output, Math.toIntExact(readLength), lastRead);
            return NO_RESULT;
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

    private static final class GCD {
        private final Arena arena;
        private final long handle;
        private final MemorySegment gcdQueue;

        private GCD(long handle) {
            this.arena = Arena.ofAuto();
            this.handle = handle;
            this.gcdQueue = UnixKernel.dispatch_queue_create(
                    arena.allocateFrom("socket_" + handle),
                    MemorySegment.NULL
            );
        }

        public CompletableFuture<Void> dispatch(DispatchEvent event) {
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

        public enum DispatchEvent {
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

        public enum BlockType {
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
}
