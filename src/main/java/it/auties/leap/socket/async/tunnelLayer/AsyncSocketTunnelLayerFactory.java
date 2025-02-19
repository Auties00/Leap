package it.auties.leap.socket.async.tunnelLayer;

import it.auties.leap.socket.SocketTunnelLayerFactory;
import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.tunnelLayer.implementation.AsyncDirectTunnelSocketLayer;
import it.auties.leap.socket.async.tunnelLayer.implementation.AsyncHTTPTunnelSocketLayer;
import it.auties.leap.socket.async.tunnelLayer.implementation.AsyncSOCKSTunnelSocketLayer;

import java.net.URI;
import java.util.Objects;

public non-sealed interface AsyncSocketTunnelLayerFactory extends SocketTunnelLayerFactory<AsyncSocketApplicationLayer> {
    static AsyncSocketTunnelLayerFactory forProxy(URI proxy) {
        if (proxy == null) {
            return AsyncSocketTunnelLayerFactory.direct();
        } else {
            var scheme = normalizedScheme(proxy);
            return switch (scheme) {
                case "http", "https" -> AsyncSocketTunnelLayerFactory.http();
                case "socks5", "socks5h", "socks4" -> AsyncSocketTunnelLayerFactory.socks();
                default -> throw new SocketException("Unknown proxy scheme: " + scheme);
            };
        }
    }

    private static String normalizedScheme(URI proxy) {
        return Objects.requireNonNull(proxy.getScheme(), "Missing scheme").toLowerCase();
    }

    static AsyncSocketTunnelLayerFactory direct() {
        return AsyncDirectTunnelSocketLayer.factory();
    }

    static AsyncSocketTunnelLayerFactory http() {
        return AsyncHTTPTunnelSocketLayer.factory();
    }

    static AsyncSocketTunnelLayerFactory socks() {
        return AsyncSOCKSTunnelSocketLayer.factory();
    }

    @Override
    AsyncSocketTunnelLayer newTunnel(AsyncSocketApplicationLayer applicationLayer, URI location);
}
