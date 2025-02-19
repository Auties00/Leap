package it.auties.leap.socket.blocking.transportLayer;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.SocketTransportLayerFactory;
import it.auties.leap.socket.blocking.transportLayer.implementation.BlockingLinuxTransportSocketLayer;
import it.auties.leap.socket.blocking.transportLayer.implementation.BlockingUnixTransportSocketLayer;
import it.auties.leap.socket.blocking.transportLayer.implementation.BlockingWinTransportSocketLayer;

public non-sealed interface BlockingSocketTransportLayerFactory extends SocketTransportLayerFactory {
    static BlockingSocketTransportLayerFactory forPlatform() {
        var os = normalizedOs();
        if(os.contains("win")) {
            return BlockingWinTransportSocketLayer.factory();
        }else if(os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            return BlockingLinuxTransportSocketLayer.factory();
        }else if(os.contains("mac")) {
            return BlockingUnixTransportSocketLayer.factory();
        }else {
            throw new SocketException("Unsupported os: " + os);
        }
    }

    private static String normalizedOs() {
        var name = System.getProperty("os.name");
        return name == null ? "unknown" : name.toLowerCase();
    }

    static BlockingSocketTransportLayerFactory windows() {
        return BlockingWinTransportSocketLayer.factory();
    }

    static BlockingSocketTransportLayerFactory linux() {
        return BlockingLinuxTransportSocketLayer.factory();
    }

    static BlockingSocketTransportLayerFactory unix() {
        return BlockingUnixTransportSocketLayer.factory();
    }
    
    @Override
    BlockingSocketTransportLayer newTransport(SocketProtocol protocol);
}
