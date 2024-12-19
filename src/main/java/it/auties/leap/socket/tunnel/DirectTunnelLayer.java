package it.auties.leap.socket.tunnel;

import it.auties.leap.socket.transmission.SocketTransmissionLayer;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;

final class DirectTunnelLayer extends SocketTunnelLayer {
    DirectTunnelLayer(SocketTransmissionLayer<?> channel) {
        super(channel, null, null);
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return transmissionLayer.connect(address);
    }
}
