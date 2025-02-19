package it.auties.leap.socket.async.transportLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;

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

abstract class AsyncNativeTransportSocketLayer<HANDLE extends Number> extends AsyncSocketTransportLayer {
    static final CompletableFuture<Void> NO_RESULT = CompletableFuture.completedFuture(null);

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

    public AsyncNativeTransportSocketLayer(SocketProtocol protocol) {
        super(protocol);
        this.arena = Arena.ofAuto();
        this.handle = createNativeHandle();
        this.ioLock = new ReentrantLock(true);
        this.connected = new AtomicBoolean(false);
        this.readBufferSize = SocketOption.readBufferSize().defaultValue();
        this.writeBufferSize = SocketOption.writeBufferSize().defaultValue();
        this.keepAlive = SocketOption.keepAlive().defaultValue();
    }

    protected abstract HANDLE createNativeHandle();

    @Override
    public final CompletableFuture<Void> connect(InetSocketAddress address) {
        if (connected.get()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: already connected"));
        }
        
        return connectNative(address);
    }

    protected abstract CompletableFuture<Void> connectNative(InetSocketAddress address);

    protected OptionalInt getLittleEndianIPV4Host(InetSocketAddress address) {
        var inetAddress = address.getAddress();
        if (inetAddress == null) {
            return OptionalInt.empty();
        }

        var result = ByteBuffer.wrap(inetAddress.getAddress())
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt();
        return OptionalInt.of(result);
    }

    @Override
    public final CompletableFuture<Void> write(ByteBuffer input) {
        if (!connected.get()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket not connected)"));
        }

        if (input == null || !input.hasRemaining()) {
            return NO_RESULT;
        }

        ioLock.lock();
        try {
            return writeNative(input);
        } finally {
            ioLock.unlock();
        }
    }

    protected abstract CompletableFuture<Void> writeNative(ByteBuffer input);

    @Override
    public final CompletableFuture<Void> read(ByteBuffer output) {
        return read(output, true);
    }

    public final CompletableFuture<Void> read(ByteBuffer output, boolean lastRead) {
        if (!connected.get()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot read message from socket (socket not connected)"));
        }

        if (!output.hasRemaining()) {
            return NO_RESULT;
        }

        ioLock.lock();
        try {
            return readNative(output, lastRead);
        } finally {
            ioLock.unlock();
        }
    }

    protected abstract CompletableFuture<Void> readNative(ByteBuffer output, boolean lastRead);

    @Override
    public <V> V getOption(SocketOption<V> option) {
        return (V) switch (option) {
            case SocketOption.KeepAlive _ -> keepAlive;
            case SocketOption.ReadBufferSize _ -> readBufferSize;
            case SocketOption.WriteBufferSize _ -> writeBufferSize;
        };
    }

    @Override
    public <V> void setOption(SocketOption<V> option, V value) {
        switch (option) {
            case SocketOption.KeepAlive _ -> this.keepAlive = (boolean) value;
            case SocketOption.ReadBufferSize _ -> this.readBufferSize = (int) value;
            case SocketOption.WriteBufferSize _ -> this.writeBufferSize = (int) value;
        }
    }

    @Override
    public abstract void close() throws IOException;

    @Override
    public boolean isConnected() {
        return connected.get();
    }

    protected void writeToIOBuffer(ByteBuffer input, int length) {
        for (int i = 0; i < length; i++) {
            writeBuffer.setAtIndex(ValueLayout.JAVA_BYTE, i, input.get());
        }
    }

    protected void readFromIOBuffer(ByteBuffer output, int readLength, boolean lastRead) {
        for (int i = 0; i < readLength; i++) {
            output.put(readBuffer.getAtIndex(ValueLayout.JAVA_BYTE, i));
        }
        if(lastRead) {
            output.flip();
        }
    }

    protected void initIOBuffers() {
        this.readBuffer = arena.allocate(ValueLayout.JAVA_BYTE, getOption(SocketOption.readBufferSize()));
        this.writeBuffer = arena.allocate(ValueLayout.JAVA_BYTE, getOption(SocketOption.writeBufferSize()));
    }

    @Override
    public Optional<InetSocketAddress> address() {
        return Optional.ofNullable(address);
    }

    @Override
    public void setAddress(InetSocketAddress address) {
        this.address = address;
    }

    @Override
    public CompletableFuture<Void> readFully(ByteBuffer buffer) {
        return read(buffer, false).thenCompose(_ -> {
            if (buffer.hasRemaining()) {
                return readFully(buffer);
            }

            buffer.flip();
            return NO_RESULT;
        });
    }
}
