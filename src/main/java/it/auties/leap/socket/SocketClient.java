package it.auties.leap.socket;

import it.auties.leap.http.decoder.HttpDecodable;
import it.auties.leap.socket.layer.SocketSecurityLayer;
import it.auties.leap.socket.layer.SocketTransmissionLayer;
import it.auties.leap.socket.layer.SocketTunnelLayer;
import it.auties.leap.tls.TlsConfig;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

@SuppressWarnings("unused")
public final class SocketClient implements HttpDecodable, AutoCloseable {
    public static SocketClient ofPlain(SocketProtocol protocol) throws IOException {
        return ofPlain(protocol, null);
    }

    public static SocketClient ofPlain(SocketProtocol protocol, URI proxy) throws IOException {
        var transmissionLayer = SocketTransmissionLayer.ofPlatform(protocol);
        var layerSupport = SocketSecurityLayer.ofPlain(transmissionLayer);
        var proxySupport = SocketTunnelLayer.of(transmissionLayer, layerSupport, proxy);
        return new SocketClient(transmissionLayer, proxySupport, layerSupport);
    }

    public static SocketClient ofSecure(SocketProtocol protocol, TlsConfig tlsConfig) throws IOException {
        return ofSecure(protocol, tlsConfig, null);
    }

    public static SocketClient ofSecure(SocketProtocol protocol, TlsConfig tlsConfig, URI proxy) throws IOException {
        var transmissionLayer = SocketTransmissionLayer.ofPlatform(protocol);
        var layerSupport = SocketSecurityLayer.ofSecure(transmissionLayer, tlsConfig);
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
                .thenComposeAsync(ignored -> securityLayer.handshake())
                .exceptionallyComposeAsync(error -> {
                    try {
                        close();
                    }catch (Throwable ignored) {

                    }

                    return CompletableFuture.failedFuture(error);
                });
    }

    public CompletableFuture<Void> upgrade(TlsConfig tlsConfig) {
        Objects.requireNonNull(tlsConfig, "Invalid TLS config");
        if(!isConnected()) {
            throw new IllegalArgumentException("The socket is not connected");
        }

        if(securityLayer.isSecure()) {
            throw new IllegalStateException("This socket is already using a secure connection");
        }

        this.securityLayer = SocketSecurityLayer.ofSecure(transmissionLayer, tlsConfig);
        return securityLayer.handshake();
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
