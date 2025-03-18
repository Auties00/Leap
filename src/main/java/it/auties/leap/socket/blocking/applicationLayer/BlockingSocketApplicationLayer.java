package it.auties.leap.socket.blocking.applicationLayer;

import it.auties.leap.socket.SocketApplicationLayer;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.blocking.BlockingSocketIO;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Optional;

public non-sealed abstract class BlockingSocketApplicationLayer implements SocketApplicationLayer, BlockingSocketIO {
    protected final BlockingSocketTransportLayer transportLayer;
    protected BlockingSocketApplicationLayer(BlockingSocketTransportLayer transportLayer) {
        this.transportLayer = transportLayer;
    }

    public void connect(InetSocketAddress address) {
        transportLayer.connect(address);
    }

    public abstract void handshake();

    @Override
    public boolean isConnected() {
        return transportLayer.isConnected();
    }

    @Override
    public Optional<InetSocketAddress> address() {
        return transportLayer.address();
    }

    @Override
    public void setAddress(InetSocketAddress address) {
        transportLayer.setAddress(address);
    }

    @Override
    public <V> V getOption(SocketOption<V> option) {
        return transportLayer.getOption(option);
    }

    @Override
    public <V> void setOption(SocketOption<V> option, V value) {
        transportLayer.setOption(option, value);
    }

    @Override
    public void close() throws IOException {
        close(false);
    }
}
