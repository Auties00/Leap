package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.SocketProtocol;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Optional;

public final class BlockingSocketClient implements SocketClient, BlockingSocketIO {
    private final BlockingSocketApplicationLayer applicationLayer;
    private final BlockingSocketTunnelLayer tunnelLayer;

    BlockingSocketClient(BlockingSocketApplicationLayer applicationLayer, BlockingSocketTunnelLayer tunnelLayer) {
        this.applicationLayer = applicationLayer;
        this.tunnelLayer = tunnelLayer;
    }
    
    public void connect(InetSocketAddress address) {
        try {
            tunnelLayer.connect(address);
            applicationLayer.handshake();
        }catch (Throwable throwable) {
            try {
                close();
            }catch (IOException closeError) {
               throwable.addSuppressed(closeError);
            }
            rethrow(throwable);
        }
    }

    @SuppressWarnings("UnusedReturnValue")
    private static RuntimeException rethrow(Throwable t) {
        return rethrow0(t);
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> T rethrow0(Throwable t) throws T {
        throw (T) t;
    }

    @Override
    public void write(ByteBuffer buffer) {
        applicationLayer.write(buffer);
    }

    @Override
    public void read(ByteBuffer buffer) {
        applicationLayer.write(buffer);
    }

    @Override
    public void readFully(ByteBuffer buffer) {
        applicationLayer.write(buffer);
    }

    @Override
    public boolean isConnected() {
        return applicationLayer.transportLayer()
                .isConnected();
    }

    @Override
    public void close() throws IOException {
        applicationLayer.transportLayer()
                .close();
    }

    @Override
    public Optional<InetSocketAddress> address() {
        return applicationLayer.transportLayer()
                .address();
    }

    @Override
    public void setAddress(InetSocketAddress address) {
        applicationLayer.transportLayer()
                .setAddress(address);
    }

    @Override
    public <V> V getOption(SocketOption<V> option) {
        return applicationLayer.transportLayer()
                .getOption(option);
    }

    @Override
    public <V> void setOption(SocketOption<V> option, V value) {
        applicationLayer.transportLayer()
                .setOption(option, value);
    }

    public static BlockingSocketClientBuilder newBuilder(SocketProtocol protocol) {
        return new BlockingSocketClientBuilder(protocol);
    }
}
