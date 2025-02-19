package it.auties.leap.socket.async;

import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public final class AsyncSocketClient implements SocketClient, AsyncSocketIO {
    private final AsyncSocketApplicationLayer applicationLayer;
    private final AsyncSocketTunnelLayer tunnelLayer;

    AsyncSocketClient(AsyncSocketApplicationLayer applicationLayer, AsyncSocketTunnelLayer tunnelLayer) {
        this.applicationLayer = applicationLayer;
        this.tunnelLayer = tunnelLayer;
    }

    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return tunnelLayer.connect(address)
                .thenCompose(_ -> applicationLayer.handshake())
                .exceptionallyCompose(throwable -> {
                    try {
                        close();
                    }catch (IOException closeError) {
                        throwable.addSuppressed(closeError);
                    }
                    return CompletableFuture.failedFuture(throwable);
                });
    }

    public CompletableFuture<Void> write(ByteBuffer buffer) {
        return applicationLayer.write(buffer);
    }

    public CompletableFuture<Void> read(ByteBuffer buffer) {
        return applicationLayer.read(buffer);
    }

    public CompletableFuture<Void> readFully(ByteBuffer buffer) {
        return applicationLayer.readFully(buffer);
    }

    public static AsyncSocketClientBuilder newBuilder(SocketProtocol protocol) {
        return new AsyncSocketClientBuilder(protocol);
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
}
