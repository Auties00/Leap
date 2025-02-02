package it.auties.leap.socket.implementation.bridge;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.implementation.foreign.unix.UnixKernel;
import it.auties.leap.socket.implementation.threading.GCD;
import it.auties.leap.socket.implementation.threading.GCD.DispatchEvent;

import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

// GCD (General Central Dispatch)
public final class UnixImplementation extends ForeignImplementation<Integer> {
    private static final UnixKernel.fcntl fcntl = UnixKernel.fcntl
            .makeInvoker(ValueLayout.JAVA_INT);
    private static final MemorySegment errno = Linker.nativeLinker()
            .defaultLookup()
            .findOrThrow("errno")
            .reinterpret(ValueLayout.JAVA_INT.byteSize());

    private GCD dispatcher;

    public UnixImplementation(SocketProtocol protocol) {
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
        return dispatcher.dispatch(DispatchEvent.WRITE).thenCompose(_ -> {
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
            return CompletableFuture.completedFuture(null);
        });
    }

    @Override
    protected CompletableFuture<Void> writeNative(ByteBuffer input) {
        var length = Math.min(input.remaining(), writeBufferSize);
        writeToIOBuffer(input, length);
        return dispatcher.dispatch(DispatchEvent.WRITE).thenCompose(_ -> {
            var result = UnixKernel.write(handle, writeBuffer, length);
            if (result == -1) {
                close();
                return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket closed)"));
            }

            if (input.hasRemaining()) {
                return writeNative(input);
            }

            return CompletableFuture.completedFuture(null);
        });
    }

    @Override
    protected CompletableFuture<ByteBuffer> readNative(ByteBuffer output) {
        return dispatcher.dispatch(DispatchEvent.READ).thenCompose(_ -> {
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
}
