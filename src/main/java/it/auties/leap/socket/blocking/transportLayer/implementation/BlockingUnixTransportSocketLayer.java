package it.auties.leap.socket.blocking.transportLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayerFactory;
import it.auties.leap.socket.implementation.unix.UnixKernel;
import it.auties.leap.socket.implementation.unix.in_addr;
import it.auties.leap.socket.implementation.win.sockaddr_in;

import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Optional;

// GCD (General Central Dispatch)
public final class BlockingUnixTransportSocketLayer extends BlockingNativeTransportSocketLayer<Integer> {
    private static final BlockingSocketTransportLayerFactory FACTORY = BlockingUnixTransportSocketLayer::new;

    public static BlockingSocketTransportLayerFactory factory() {
        return FACTORY;
    }

    private static final UnixKernel.fcntl fcntl = UnixKernel.fcntl
            .makeInvoker(ValueLayout.JAVA_INT);
    private static final MemorySegment errno = Linker.nativeLinker()
            .defaultLookup()
            .findOrThrow("errno")
            .reinterpret(ValueLayout.JAVA_INT.byteSize());

    public BlockingUnixTransportSocketLayer(SocketProtocol protocol) {
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
    public void connectNative(InetSocketAddress address) {
        var remoteAddress = createRemoteAddress(address);
        if (remoteAddress.isEmpty()) {
            throw new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName()));
        }

        var response = UnixKernel.connect(
                handle,
                remoteAddress.get(),
                (int) remoteAddress.get().byteSize()
        );
        if (response != -1) {
            throw new SocketException("Cannot connect to socket remote connection failure (async operation expected)");
        }

        var errorCode = getErrorCode();
        if (errorCode != UnixKernel.EINPROGRESS() && errorCode != UnixKernel.ETIMEDOUT()) {
            throw new SocketException("Cannot connect to socket: remote connection failure (error code: %s)".formatted(errorCode));
        }

        initIOBuffers();

        var errorSegment = arena.allocate(ValueLayout.JAVA_INT);
        var result = UnixKernel.getsockopt(
                handle,
                UnixKernel.SOL_SOCKET(),
                UnixKernel.SO_ERROR(),
                errorSegment,
                arena.allocateFrom(ValueLayout.JAVA_INT, (int) errorSegment.byteSize())
        );
        if (result < 0) {
            throw new SocketException("Cannot connect to socket: cannot get result (error code: %s)".formatted(result));
        }

        var error = errorSegment.get(ValueLayout.JAVA_INT, 0);
        if (error != 0) {
            throw new SocketException("Cannot connect to socket: remote connection failure (error code: %s)".formatted(error));
        }

        connected.set(true);
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
    protected void writeNative(ByteBuffer input) {
        while (input.hasRemaining()) {
            var length = Math.min(input.remaining(), writeBufferSize);
            writeToIOBuffer(input, length);
            var result = UnixKernel.write(handle, writeBuffer, length);
            if (result == -1) {
                close();
                throw new SocketException("Cannot send message to socket (socket closed)");
            }
        }
    }

    @Override
    protected void readNative(ByteBuffer output, boolean lastRead) {
        var length = Math.min(output.remaining(), readBufferSize);
        var readLength = UnixKernel.read(handle, readBuffer, length);
        if (readLength <= 0) {
            close();
            throw new SocketException("Cannot receive message from socket (socket closed)");
        }

        readFromIOBuffer(output, Math.toIntExact(readLength), lastRead);
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
