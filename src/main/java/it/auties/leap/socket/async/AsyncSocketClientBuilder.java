package it.auties.leap.socket.async;

import it.auties.leap.socket.SocketClientBuilder;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayerFactory;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayerFactory;
import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayerFactory;
import it.auties.leap.tls.context.TlsContext;

import java.net.URI;
import java.util.Objects;

@SuppressWarnings({"rawtypes", "unchecked"})
public final class AsyncSocketClientBuilder extends SocketClientBuilder {
    private final SocketProtocol protocol;
    private AsyncSocketApplicationLayerFactory applicationFactory;
    private Object applicationParameter;
    private AsyncSocketTransportLayerFactory transportFactory;
    private AsyncSocketTunnelLayerFactory tunnelFactory;
    private URI tunnelLocation;

    AsyncSocketClientBuilder(SocketProtocol protocol) {
        this.protocol = protocol;
    }

    public AsyncSocketClientBuilder transportLayer(AsyncSocketTransportLayerFactory transportFactory) {
        this.transportFactory = transportFactory;
        return this;
    }

    public <P> AsyncSocketClientBuilder applicationLayer(AsyncSocketApplicationLayerFactory<P> factory, P param) {
        this.applicationFactory = factory;
        this.applicationParameter = param;
        return this;
    }

    public AsyncSocketClientBuilder tunnelLayer(AsyncSocketTunnelLayerFactory tunnelFactory, URI tunnelLocation) {
        this.tunnelFactory = tunnelFactory;
        this.tunnelLocation = tunnelLocation;
        return this;
    }

    public AsyncSocketClientBuilder secure(TlsContext context) {
        this.applicationFactory = AsyncSocketApplicationLayerFactory.secure();
        this.applicationParameter = context;
        return this;
    }

    public AsyncSocketClientBuilder plain() {
        this.applicationFactory = AsyncSocketApplicationLayerFactory.plain();
        this.applicationParameter = null;
        return this;
    }

    public AsyncSocketClientBuilder proxy(URI proxy) {
        if(proxy == null) {
            this.tunnelFactory = null;
            this.tunnelLocation = null;
        }else {
            this.tunnelFactory = AsyncSocketTunnelLayerFactory.forProxy(proxy);
            this.tunnelLocation = proxy;
        }
        return this;
    }

    public AsyncSocketClient build() {
        var transport = Objects.requireNonNullElseGet(transportFactory, AsyncSocketTransportLayerFactory::forPlatform)
                .newTransport(protocol);
        var application = Objects.requireNonNullElseGet(applicationFactory, AsyncSocketApplicationLayerFactory::secure)
                .newApplication(transport, applicationParameter);
        var tunnel = Objects.requireNonNullElseGet(tunnelFactory, AsyncSocketTunnelLayerFactory::direct)
                .newTunnel(application, tunnelLocation);
        return new AsyncSocketClient(application, tunnel);
    }
}
