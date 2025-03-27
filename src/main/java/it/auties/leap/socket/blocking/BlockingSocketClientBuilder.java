package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketClientBuilder;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayerFactory;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayerFactory;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayerFactory;
import it.auties.leap.tls.context.TlsContext;

import java.net.URI;
import java.util.Objects;

@SuppressWarnings({"rawtypes", "unchecked"})
public final class BlockingSocketClientBuilder extends SocketClientBuilder {
    private final SocketProtocol protocol;
    private BlockingSocketApplicationLayerFactory applicationFactory;
    private Object applicationParameter;
    private BlockingSocketTransportLayerFactory transportFactory;
    private BlockingSocketTunnelLayerFactory tunnelFactory;
    private URI tunnelLocation;

    BlockingSocketClientBuilder(SocketProtocol protocol) {
        this.protocol = protocol;
    }

    public BlockingSocketClientBuilder transportLayer(BlockingSocketTransportLayerFactory transportFactory) {
        this.transportFactory = transportFactory;
        return this;
    }

    public <P> BlockingSocketClientBuilder applicationLayer(BlockingSocketApplicationLayerFactory<P> factory, P param) {
        this.applicationFactory = factory;
        this.applicationParameter = param;
        return this;
    }

    public BlockingSocketClientBuilder tunnelLayer(BlockingSocketTunnelLayerFactory tunnelFactory, URI tunnelLocation) {
        this.tunnelFactory = tunnelFactory;
        this.tunnelLocation = tunnelLocation;
        return this;
    }

    public BlockingSocketClientBuilder secure(TlsContext context) {
        this.applicationFactory = BlockingSocketApplicationLayerFactory.secure();
        this.applicationParameter = context;
        return this;
    }

    public BlockingSocketClientBuilder plain() {
        this.applicationFactory = BlockingSocketApplicationLayerFactory.plain();
        this.applicationParameter = null;
        return this;
    }

    public BlockingSocketClientBuilder proxy(URI proxy) {
        if (proxy == null) {
            this.tunnelFactory = null;
            this.tunnelLocation = null;
        } else {
            this.tunnelFactory = BlockingSocketTunnelLayerFactory.forProxy(proxy);
            this.tunnelLocation = proxy;
        }
        return this;
    }

    public BlockingSocketClient build() {
        var transport = Objects.requireNonNullElseGet(transportFactory, BlockingSocketTransportLayerFactory::forPlatform)
                .newTransport(protocol);
        var application = Objects.requireNonNullElseGet(applicationFactory, BlockingSocketApplicationLayerFactory::secure)
                .newApplication(transport, applicationParameter);
        var tunnel = Objects.requireNonNullElseGet(tunnelFactory, BlockingSocketTunnelLayerFactory::direct)
                .newTunnel(application, tunnelLocation);
        return new BlockingSocketClient(application, tunnel);
    }
}
