package it.auties.leap.socket;

import it.auties.leap.http.decoder.HttpDecodable;
import it.auties.leap.socket.layer.SocketSecurityLayer;
import it.auties.leap.socket.layer.SocketTransmissionLayer;
import it.auties.leap.socket.layer.SocketTunnelLayer;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.*;

@SuppressWarnings("unused")
public final class SocketClient implements HttpDecodable, AutoCloseable {
    public static SocketClient ofPlain() throws IOException {
        return ofPlain(null);
    }

    public static SocketClient ofPlain(URI proxy) throws IOException {
        var transmissionLayer = SocketTransmissionLayer.ofPlatform();
        var layerSupport = SocketSecurityLayer.ofPlain(transmissionLayer);
        var proxySupport = SocketTunnelLayer.of(transmissionLayer, layerSupport, proxy);
        return new SocketClient(transmissionLayer, proxySupport, layerSupport);
    }

    public static SocketClient ofSecure(SSLContext sslContext, SSLParameters sslParameters) throws IOException {
        return ofSecure(sslContext, sslParameters, null);
    }

    public static SocketClient ofSecure(SSLContext sslContext, SSLParameters sslParameters, URI proxy) throws IOException {
        var transmissionLayer = SocketTransmissionLayer.ofPlatform();
        var layerSupport = SocketSecurityLayer.ofSecure(transmissionLayer, sslContext, sslParameters);
        var proxySupport = SocketTunnelLayer.of(transmissionLayer, layerSupport, proxy);
        return new SocketClient(transmissionLayer, proxySupport, layerSupport);
    }

    final SocketTransmissionLayer<?> transmissionLayer;
    final SocketTunnelLayer tunnelLayer;
    SocketSecurityLayer securityLayer;
    private SocketClient(SocketTransmissionLayer<?> transmissionLayer, SocketTunnelLayer tunnelLayer, SocketSecurityLayer securityLayer) {
        this.transmissionLayer = transmissionLayer;
        this.tunnelLayer = tunnelLayer;
        this.securityLayer = securityLayer;
    }

    public CompletableFuture<Void> connect(InetSocketAddress address) {
        if(isConnected()) {
            return CompletableFuture.completedFuture(null);
        }

        return tunnelLayer.connect(address)
                .thenComposeAsync(ignored -> securityLayer.handshake(address.getHostName(), address.getPort()))
                .exceptionallyComposeAsync(error -> {
                    try {
                        close();
                    }catch (Throwable ignored) {

                    }

                    return CompletableFuture.failedFuture(error);
                });
    }

    public CompletableFuture<Void> upgrade(SSLContext sslContext, SSLParameters sslParameters) {
        if(!isConnected()) {
            throw new IllegalArgumentException("The socket is not connected");
        }

        if(securityLayer.isSecure()) {
            throw new IllegalStateException("This socket is already using a secure connection");
        }

        this.securityLayer = SocketSecurityLayer.ofSecure(transmissionLayer, sslContext, sslParameters);
        var address = remoteSocketAddress()
                .orElseThrow(() -> new InternalError("Socket is supposed to be connected, but no remote address was set"));
        return securityLayer.handshake(address.getHostName(), address.getPort());
    }

    @Override
    public void close() throws IOException {
        transmissionLayer.close();
    }

    public boolean isConnected() {
        return transmissionLayer.isConnected();
    }

    public Optional<InetSocketAddress> remoteSocketAddress() {
        return transmissionLayer.address();
    }

    public <V> void setOption(SocketOption<V> option, V value) throws SocketException {
        transmissionLayer.setOption(option, value);
    }

    public <V> V getOption(SocketOption<V> option) {
        return transmissionLayer.getOption(option);
    }

    public CompletableFuture<Void> write(byte[] data) {
        return write(data, 0, data.length);
    }

    public CompletableFuture<Void> write(byte[] data, int offset, int length) {
        return write(ByteBuffer.wrap(data, offset, length));
    }

    public CompletableFuture<Void> write(ByteBuffer buffer) {
        return securityLayer.write(buffer);
    }

    @Override
    public CompletableFuture<ByteBuffer> read() {
        return securityLayer.read();
    }

    public CompletableFuture<ByteBuffer> read(ByteBuffer buffer) {
        return securityLayer.read(buffer, true);
    }

    @Override
    public CompletableFuture<ByteBuffer> readFully(int length) {
        return securityLayer.readFully(length);
    }

    private CompletableFuture<ByteBuffer> readFully(ByteBuffer buffer) {
        return securityLayer.readFully(buffer);
    }
}
