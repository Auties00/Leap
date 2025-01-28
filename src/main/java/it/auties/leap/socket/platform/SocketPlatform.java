package it.auties.leap.socket.platform;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.platform.ffi.shared.in_addr;
import it.auties.leap.socket.platform.ffi.shared.sockaddr_in;
import it.auties.leap.socket.platform.ffi.win.WindowsKernel;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

public abstract class SocketPlatform<HANDLE extends Number> implements AutoCloseable {
    protected final SocketProtocol protocol;
    protected final Arena arena;
    protected final HANDLE handle;
    protected final ReentrantLock ioLock;
    protected final AtomicBoolean connected;
    protected InetSocketAddress address;
    protected MemorySegment readBuffer;
    protected int readBufferSize;
    protected MemorySegment writeBuffer;
    protected int writeBufferSize;
    protected boolean keepAlive;

    protected SocketPlatform(SocketProtocol protocol) {
        this.protocol = protocol;
        this.arena = Arena.ofAuto();
        this.handle = createHandle();
        this.ioLock = new ReentrantLock(true);
        this.connected = new AtomicBoolean(false);
        this.readBufferSize = SocketOption.readBufferSize().defaultValue();
        this.writeBufferSize = SocketOption.writeBufferSize().defaultValue();
        this.keepAlive = SocketOption.keepAlive().defaultValue();
    }

    protected abstract HANDLE createHandle();

    public abstract CompletableFuture<Void> connect(InetSocketAddress address);

    public CompletableFuture<Void> write(ByteBuffer input) {
        if (!connected.get()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket not connected)"));
        }

        if (input == null || !input.hasRemaining()) {
            return CompletableFuture.completedFuture(null);
        }

        ioLock.lock();
        try {
            return writeUnchecked(input);
        } finally {
            ioLock.unlock();
        }
    }

    protected abstract CompletableFuture<Void> writeUnchecked(ByteBuffer input);

    public CompletableFuture<ByteBuffer> read(ByteBuffer output) {
        if (!connected.get()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot read message from socket (socket not connected)"));
        }

        if (!output.hasRemaining()) {
            return CompletableFuture.completedFuture(output);
        }

        ioLock.lock();
        try {
            return readUnchecked(output);
        } finally {
            ioLock.unlock();
        }
    }

    protected abstract CompletableFuture<ByteBuffer> readUnchecked(ByteBuffer output);

    public <V> void setOption(SocketOption<V> option, V value) {
        switch (option) {
            case SocketOption.KeepAlive _ -> this.keepAlive = (boolean) value;
            case SocketOption.ReadBufferSize _ -> this.readBufferSize = (int) value;
            case SocketOption.WriteBufferSize _ -> this.writeBufferSize = (int) value;
        }
    }

    public <V> V getOption(SocketOption<V> option) {
        return (V) switch (option) {
            case SocketOption.KeepAlive _ -> keepAlive;
            case SocketOption.ReadBufferSize _ -> readBufferSize;
            case SocketOption.WriteBufferSize _ -> writeBufferSize;
        };
    }

    @Override
    public abstract void close() throws IOException;

    public boolean isConnected() {
        return connected.get();
    }

    protected Optional<MemorySegment> createRemoteAddress(InetSocketAddress address) {
        var remoteAddress = arena.allocate(sockaddr_in.layout());
        sockaddr_in.sin_family(remoteAddress, (short) WindowsKernel.AF_INET());
        sockaddr_in.sin_port(remoteAddress, Short.reverseBytes((short) address.getPort()));
        var inAddr = arena.allocate(in_addr.layout());
        var ipv4Host = getLittleEndianIPV4Host(address);
        if (ipv4Host.isEmpty()) {
            return Optional.empty();
        }

        in_addr.S_un(inAddr, arena.allocateFrom(WindowsKernel.ULONG, ipv4Host.getAsInt()));
        sockaddr_in.sin_addr(remoteAddress, inAddr);
        return Optional.of(remoteAddress);
    }

    private OptionalInt getLittleEndianIPV4Host(InetSocketAddress address) {
        var inetAddress = address.getAddress();
        if (inetAddress == null) {
            return OptionalInt.empty();
        }

        var result = ByteBuffer.wrap(inetAddress.getAddress())
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt();
        return OptionalInt.of(result);
    }

    protected void writeToIOBuffer(ByteBuffer input, int length) {
        for (int i = 0; i < length; i++) {
            writeBuffer.setAtIndex(ValueLayout.JAVA_BYTE, i, input.get());
        }
    }

    protected void readFromIOBuffer(ByteBuffer output, int readLength) {
        for (int i = 0; i < readLength; i++) {
            output.put(readBuffer.getAtIndex(ValueLayout.JAVA_BYTE, i));
        }
    }

    protected void initIOBuffers() {
        this.readBuffer = arena.allocate(ValueLayout.JAVA_BYTE, getOption(SocketOption.readBufferSize()));
        this.writeBuffer = arena.allocate(ValueLayout.JAVA_BYTE, getOption(SocketOption.writeBufferSize()));
    }

    public Optional<InetSocketAddress> address() {
        return Optional.ofNullable(address);
    }

    public void setAddress(InetSocketAddress address) {
        this.address = address;
    }
}
