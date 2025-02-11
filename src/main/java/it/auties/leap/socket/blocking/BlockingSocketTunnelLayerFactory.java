package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketTunnelLayerFactory;
import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingDirectTunnelSocketLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingHTTPTunnelSocketLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSOCKSTunnelSocketLayer;

import java.net.URI;
import java.util.Objects;

public non-sealed interface BlockingSocketTunnelLayerFactory extends SocketTunnelLayerFactory<BlockingSocketApplicationLayer> {
    static BlockingSocketTunnelLayerFactory forProxy(URI proxy) {
        if (proxy == null) {
            return BlockingSocketTunnelLayerFactory.direct();
        } else {
            var scheme = normalizedScheme(proxy);
            return switch (scheme) {
                case "http", "https" -> BlockingSocketTunnelLayerFactory.http();
                case "socks5", "socks5h", "socks4" -> BlockingSocketTunnelLayerFactory.socks();
                default -> throw new SocketException("Unknown proxy scheme: " + scheme);
            };
        }
    }

    private static String normalizedScheme(URI proxy) {
        return Objects.requireNonNull(proxy.getScheme(), "Missing scheme").toLowerCase();
    }

    static BlockingSocketTunnelLayerFactory direct() {
        return BlockingDirectTunnelSocketLayer.factory();
    }

    static BlockingSocketTunnelLayerFactory http() {
        return BlockingHTTPTunnelSocketLayer.factory();
    }

    static BlockingSocketTunnelLayerFactory socks() {
        return BlockingSOCKSTunnelSocketLayer.factory();
    }
    
    @Override
    BlockingSocketTunnelLayer newTunnel(BlockingSocketApplicationLayer applicationLayer, URI location);
}
