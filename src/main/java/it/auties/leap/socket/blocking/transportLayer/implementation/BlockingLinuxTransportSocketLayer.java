package it.auties.leap.socket.blocking.transportLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayerFactory;
import it.auties.leap.socket.kernel.linux.LinuxKernel;
import it.auties.leap.socket.kernel.linux.in_addr;
import it.auties.leap.socket.kernel.linux.sockaddr_in;

import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Optional;

// Io_uring
public final class BlockingLinuxTransportSocketLayer extends BlockingNativeTransportSocketLayer<Integer> {
    private static final BlockingSocketTransportLayerFactory FACTORY = BlockingLinuxTransportSocketLayer::new;

    public static BlockingSocketTransportLayerFactory factory() {
        return FACTORY;
    }

    public BlockingLinuxTransportSocketLayer(SocketProtocol protocol) {
        super(protocol);
    }

    @Override
    protected Integer createNativeHandle() {
        var handle = LinuxKernel.socket(
                LinuxKernel.AF_INET(),
                LinuxKernel.SOCK_STREAM(),
                0
        );
        if (handle == -1) {
            throw new SocketException("Cannot create socket");
        }
        return handle;
    }

    @Override
    public void connectNative(InetSocketAddress address) {
        var remoteAddress = createRemoteAddress(address);
        if (remoteAddress.isEmpty()) {
            throw new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName()));
        }

        initIOBuffers();

        var result = LinuxKernel.connect(handle, remoteAddress.get(), (int) remoteAddress.get().byteSize());
        if(result < 0) {
            throw new SocketException("Cannot connect to socket: operation failed with error code " + result);
        }

        connected.set(true);
    }

    private Optional<MemorySegment> createRemoteAddress(InetSocketAddress address) {
        var remoteAddress = arena.allocate(sockaddr_in.layout());
        sockaddr_in.sin_family(remoteAddress, (short) LinuxKernel.AF_INET());
        sockaddr_in.sin_port(remoteAddress, Short.reverseBytes((short) address.getPort()));
        var inAddr = arena.allocate(in_addr.layout());
        var ipv4Host = getLittleEndianIPV4Host(address);
        if (ipv4Host.isEmpty()) {
            return Optional.empty();
        }

        in_addr.s_addr(inAddr, ipv4Host.getAsInt());
        sockaddr_in.sin_addr(remoteAddress, inAddr);
        return Optional.of(remoteAddress);
    }
    
    @Override
    protected void writeNative(ByteBuffer data) {
        while (data.hasRemaining()) {
            var length = Math.min(data.remaining(), writeBufferSize);
            writeToIOBuffer(data, length);
            var result = LinuxKernel.write(handle, writeBuffer, length);
            if(result < 0) {
                close();
                throw new SocketException("Cannot send message to socket (socket closed)");
            }
        }
    }

    @Override
    protected void readNative(ByteBuffer data, boolean lastRead) {
        var length = Math.min(data.remaining(), readBufferSize);
        var readLength = LinuxKernel.read(handle, readBuffer, length);
        if (readLength == 0) {
            close();
            throw new SocketException("Cannot receive message from socket (socket closed)");
        }

        readFromIOBuffer(data, (int) readLength, lastRead);
    }

    @Override
    public void close() {
        if (!connected.get()) {
            return;
        }

        this.address = null;
        connected.set(false);

        if (handle != null) {
            LinuxKernel.shutdown(handle, LinuxKernel.SHUT_RDWR());
            LinuxKernel.close(handle);
        }
    }
}
