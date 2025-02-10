package it.auties.leap.socket.async;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.SocketTransportLayerFactory;
import it.auties.leap.socket.async.transportLayer.AsyncLinuxTransportSocketLayer;
import it.auties.leap.socket.async.transportLayer.AsyncUnixTransportSocketLayer;
import it.auties.leap.socket.async.transportLayer.AsyncWinTransportSocketLayer;

public non-sealed interface AsyncSocketTransportLayerFactory extends SocketTransportLayerFactory {
    static AsyncSocketTransportLayerFactory forPlatform() {
        var os = normalizedOs();
        if(os.contains("win")) {
            return AsyncWinTransportSocketLayer.factory();
        }else if(os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            return AsyncLinuxTransportSocketLayer.factory();
        }else if(os.contains("mac")) {
            return AsyncUnixTransportSocketLayer.factory();
        }else {
            throw new SocketException("Unsupported os: " + os);
        }
    }

    private static String normalizedOs() {
        var name = System.getProperty("os.name");
        return name == null ? "unknown" : name.toLowerCase();
    }

    static AsyncSocketTransportLayerFactory windows() {
        return AsyncWinTransportSocketLayer.factory();
    }

    static AsyncSocketTransportLayerFactory linux() {
        return AsyncLinuxTransportSocketLayer.factory();
    }

    static AsyncSocketTransportLayerFactory unix() {
        return AsyncUnixTransportSocketLayer.factory();
    }

    @Override
    AsyncSocketTransportLayer newTransport(SocketProtocol protocol);
}
