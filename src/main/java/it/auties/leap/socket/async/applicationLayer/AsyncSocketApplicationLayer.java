package it.auties.leap.socket.async.applicationLayer;

import it.auties.leap.socket.SocketApplicationLayer;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.async.AsyncSocketIO;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;

import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public non-sealed abstract class AsyncSocketApplicationLayer implements SocketApplicationLayer, AsyncSocketIO {
    protected final AsyncSocketTransportLayer transportLayer;
    protected AsyncSocketApplicationLayer(AsyncSocketTransportLayer transportLayer) {
        this.transportLayer = transportLayer;
    }

    public CompletableFuture<Void> connect(InetSocketAddress inetSocketAddress) {
        return transportLayer.connect(inetSocketAddress);
    }

    public abstract CompletableFuture<Void> handshake();

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
}
