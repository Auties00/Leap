package it.auties.leap.socket.implementation.bridge;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.implementation.foreign.linux.LinuxKernel;
import it.auties.leap.socket.implementation.foreign.linux.io_uring_sqe;
import it.auties.leap.socket.implementation.threading.IOUring;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

// Io_uring
public final class LinuxImplementation extends ForeignImplementation<Integer> {
    private IOUring ioUring;

    public LinuxImplementation(SocketProtocol protocol) {
        super(protocol);
    }

    @Override
    protected Integer createNativeHandle() {
        var handle = LinuxKernel.socket(
                LinuxKernel.AF_INET(),
                LinuxKernel.SOCK_STREAM() | LinuxKernel.SOCK_NONBLOCK(),
                0
        );
        if (handle == -1) {
            throw new SocketException("Cannot create socket");
        }
        return handle;
    }

    @Override
    public CompletableFuture<Void> connectNative(InetSocketAddress address) {
        var remoteAddress = createRemoteAddress(address);
        if (remoteAddress.isEmpty()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName())));
        }

        initIOBuffers();

        this.ioUring = IOUring.shared();
        ioUring.registerHandle(handle);

        return ioUring.prepareAsyncOperation(handle, sqe -> {
            io_uring_sqe.opcode(sqe, (byte) LinuxKernel.IORING_OP_CONNECT());
            io_uring_sqe.fd(sqe, handle);
            io_uring_sqe.addr(sqe, remoteAddress.get().address());
            io_uring_sqe.off(sqe, remoteAddress.get().byteSize());
            io_uring_sqe.user_data(sqe, handle);
        }).thenCompose(result -> {
            if (result != 0) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: operation failed with error code " + result));
            }

            connected.set(true);
            return CompletableFuture.completedFuture(null);
        });
    }

    @Override
    protected CompletableFuture<Void> writeNative(ByteBuffer data) {
        return ioUring.prepareAsyncOperation(handle, sqe -> {
            var length = Math.min(data.remaining(), writeBufferSize);
            writeToIOBuffer(data, length);
            io_uring_sqe.fd(sqe, handle);
            io_uring_sqe.opcode(sqe, (byte) LinuxKernel.IORING_OP_WRITE());
            io_uring_sqe.addr(sqe, writeBuffer.address());
            io_uring_sqe.len(sqe, length);
            io_uring_sqe.user_data(sqe, handle);
        }).thenCompose(result -> {
            if (result < 0) {
                return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (error code: %s)".formatted(result)));
            }

            if (!data.hasRemaining()) {
                return CompletableFuture.completedFuture(null);
            }

            return writeNative(data);
        });
    }

    @Override
    protected CompletableFuture<ByteBuffer> readNative(ByteBuffer data) {
        var caller = new RuntimeException();
        return ioUring.prepareAsyncOperation(handle, sqe -> {
            var length = Math.min(data.remaining(), readBufferSize);
            io_uring_sqe.opcode(sqe, (byte) LinuxKernel.IORING_OP_READ());
            io_uring_sqe.fd(sqe, handle);
            io_uring_sqe.addr(sqe, readBuffer.address());
            io_uring_sqe.len(sqe, length);
            io_uring_sqe.off(sqe, 0);
            io_uring_sqe.user_data(sqe, handle);
        }).thenCompose(readLength -> {
            if (readLength == 0) {
                close();
                return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socket closed)", caller));
            }

            readFromIOBuffer(data, readLength);
            return CompletableFuture.completedFuture(data);
        });
    }

    @Override
    public void close() {
        if (!connected.get()) {
            return;
        }

        this.address = null;
        connected.set(false);
        if (ioUring != null) {
            ioUring.unregisterHandle(handle);
        }

        if (handle != null) {
            LinuxKernel.shutdown(handle, LinuxKernel.SHUT_RDWR());
            LinuxKernel.close(handle);
        }
    }
}
