package it.auties.leap.socket.async.client.applicationLayer;

import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.async.AsyncSocketImplementation;
import it.auties.leap.socket.async.client.AsyncSocketClient;
import it.auties.leap.socket.async.client.AsyncSocketClientTunnel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class AsyncPlainSocketClient implements AsyncSocketClient {
    private final AsyncSocketImplementation implementation;
    private final AsyncSocketClientTunnel tunnelLayer;

    public AsyncPlainSocketClient(AsyncSocketImplementation implementation, AsyncSocketClientTunnel tunnel) {
        this.implementation = implementation;
        this.tunnelLayer = tunnel;
    }

    @Override
    public AsyncSocketImplementation implementation() {
        return implementation;
    }

    @Override
    public void close() throws IOException {
        implementation.close();
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return tunnelOrConnect(address)
                .exceptionallyCompose(this::closeSilently);
    }


    private CompletableFuture<Void> closeSilently(Throwable throwable) {
        try {
            close();
        }catch (Throwable _) {

        }
        return CompletableFuture.failedFuture(throwable);
    }

    private CompletableFuture<Void> tunnelOrConnect(InetSocketAddress address) {
        if (tunnelLayer != null) {
            return tunnelLayer.connect(address);
        }else {
            return implementation.connect(address);
        }
    }

    @Override
    public CompletableFuture<Void> write(ByteBuffer buffer) {
        return implementation.write(buffer);
    }

    @Override
    public CompletableFuture<Void> read(ByteBuffer buffer) {
        return implementation.read(buffer);
    }

    @Override
    public CompletableFuture<Void> readFully(ByteBuffer buffer) {
        return implementation.readFully(buffer);
    }

    @Override
    public boolean isConnected() {
        return implementation.isConnected();
    }

    @Override
    public Optional<InetSocketAddress> address() {
        return implementation.address();
    }

    @Override
    public void setAddress(InetSocketAddress address) {
        implementation.setAddress(address);
    }

    @Override
    public <V> V getOption(SocketOption<V> option) {
        return implementation.getOption(option);
    }

    @Override
    public <V> void setOption(SocketOption<V> option, V value) {
        implementation.setOption(option, value);
    }
}
