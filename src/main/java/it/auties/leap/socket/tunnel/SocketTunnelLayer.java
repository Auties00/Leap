package it.auties.leap.socket.tunnel;

import it.auties.leap.socket.security.SocketSecurityLayer;
import it.auties.leap.socket.transmission.SocketTransmissionLayer;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;

public sealed abstract class SocketTunnelLayer permits DirectTunnelLayer, HttpTunnelLayer, SocksTunnelLayer {
    final SocketTransmissionLayer<?> transmissionLayer;
    final SocketSecurityLayer securityLayer;
    final URI proxy;

    SocketTunnelLayer(SocketTransmissionLayer<?> transmissionLayer, SocketSecurityLayer securityLayer, URI proxy) {
        this.transmissionLayer = transmissionLayer;
        this.securityLayer = securityLayer;
        this.proxy = proxy;
    }

    public static SocketTunnelLayer of(SocketTransmissionLayer<?> channel, SocketSecurityLayer securityLayer, URI proxy) {
        return switch (toProxy(proxy).type()) {
            case DIRECT -> new DirectTunnelLayer(channel);
            case HTTP -> new HttpTunnelLayer(channel, securityLayer, proxy);
            case SOCKS -> new SocksTunnelLayer(channel, securityLayer, proxy);
        };
    }

    private static Proxy toProxy(URI uri) {
        if (uri == null) {
            return Proxy.NO_PROXY;
        }

        var scheme = Objects.requireNonNull(uri.getScheme(), "Invalid proxy, expected a scheme: %s".formatted(uri));
        var host = Objects.requireNonNull(uri.getHost(), "Invalid proxy, expected a host: %s".formatted(uri));
        var port = getDefaultPort(scheme, uri.getPort()).orElseThrow(() -> new NullPointerException("Invalid proxy, expected a port: %s".formatted(uri)));
        return switch (scheme.toLowerCase()) {
            case "http", "https" -> new Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(host, port));
            case "socks5", "socks5h" -> new Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(host, port));
            default -> throw new IllegalStateException("Unexpected scheme: " + scheme);
        };
    }

    private static OptionalInt getDefaultPort(String scheme, int port) {
        return port != -1 ? OptionalInt.of(port) : switch (scheme.toLowerCase()) {
            case "http" -> OptionalInt.of(80);
            case "https" -> OptionalInt.of(443);
            default -> OptionalInt.empty();
        };
    }

    public abstract CompletableFuture<Void> connect(InetSocketAddress address);
}
