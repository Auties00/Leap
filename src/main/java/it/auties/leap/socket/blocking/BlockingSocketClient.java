package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayer;

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
        applicationLayer.read(buffer);
    }

    @Override
    public void readFully(ByteBuffer buffer) {
        applicationLayer.readFully(buffer);
    }

    @Override
    public boolean isConnected() {
        return applicationLayer.isConnected();
    }

    @Override
    public void close() throws IOException {
        // TODO: Await all operations
        applicationLayer.close(false);
    }

    @Override
    public Optional<InetSocketAddress> address() {
        return applicationLayer.address();
    }

    @Override
    public void setAddress(InetSocketAddress address) {
        applicationLayer.setAddress(address);
    }

    @Override
    public <V> V getOption(SocketOption<V> option) {
        return applicationLayer.getOption(option);
    }

    @Override
    public <V> void setOption(SocketOption<V> option, V value) {
        applicationLayer.setOption(option, value);
    }

    public static BlockingSocketClientBuilder builder(SocketProtocol protocol) {
        return new BlockingSocketClientBuilder(protocol);
    }
}
