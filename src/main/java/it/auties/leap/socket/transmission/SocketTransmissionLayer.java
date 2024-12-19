package it.auties.leap.socket.transmission;

import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.transmission.ffi.in_addr;
import it.auties.leap.socket.transmission.ffi.sockaddr_in;
import it.auties.leap.socket.transmission.ffi.win.*;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

public sealed abstract class SocketTransmissionLayer<HANDLE extends Number> implements AutoCloseable permits LinuxTransmissionLayer, UnixTransmissionLayer, WindowsTransmissionLayer {
    final SocketProtocol protocol;
    final Arena arena;
    final HANDLE handle;
    final ReentrantLock ioLock;
    final AtomicBoolean connected;
    InetSocketAddress address;
    MemorySegment readBuffer;
    int readBufferSize;
    MemorySegment writeBuffer;
    int writeBufferSize;
    boolean keepAlive;

    SocketTransmissionLayer(SocketProtocol protocol) throws SocketException {
        this.protocol = protocol;
        this.arena = Arena.ofAuto();
        this.handle = createHandle();
        this.ioLock = new ReentrantLock(true);
        this.connected = new AtomicBoolean(false);
        this.readBufferSize = SocketOption.readBufferSize().defaultValue();
        this.writeBufferSize = SocketOption.writeBufferSize().defaultValue();
        this.keepAlive = SocketOption.keepAlive().defaultValue();
    }

    public static SocketTransmissionLayer<?> ofPlatform(SocketProtocol protocol) throws SocketException {
        var os = System.getProperty("os.name").toLowerCase();
        if(os.contains("win")) {
            return new WindowsTransmissionLayer(protocol);
        }else if(os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            return new LinuxTransmissionLayer(protocol);
        }else if(os.contains("mac")) {
            return new UnixTransmissionLayer(protocol);
        }else {
            throw new IllegalArgumentException("Unsupported os: " + os);
        }
    }

    abstract HANDLE createHandle() throws SocketException;

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

    public <V> void setOption(SocketOption<V> option, V value) throws SocketException {
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

    Optional<MemorySegment> createRemoteAddress(InetSocketAddress address) {
        var remoteAddress = arena.allocate(sockaddr_in.layout());
        sockaddr_in.sin_family(remoteAddress, (short) WindowsSockets.AF_INET());
        sockaddr_in.sin_port(remoteAddress, Short.reverseBytes((short) address.getPort()));
        var inAddr = arena.allocate(in_addr.layout());
        var ipv4Host = getLittleEndianIPV4Host(address);
        if (ipv4Host.isEmpty()) {
            return Optional.empty();
        }

        in_addr.S_un(inAddr, arena.allocateFrom(WindowsSockets.ULONG, ipv4Host.getAsInt()));
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

    void writeToIOBuffer(ByteBuffer input, int length) {
        for (int i = 0; i < length; i++) {
            writeBuffer.setAtIndex(ValueLayout.JAVA_BYTE, i, input.get());
        }
    }

    void readFromIOBuffer(ByteBuffer output, int readLength) {
        for (int i = 0; i < readLength; i++) {
            output.put(readBuffer.getAtIndex(ValueLayout.JAVA_BYTE, i));
        }
    }

    void initIOBuffers() {
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
