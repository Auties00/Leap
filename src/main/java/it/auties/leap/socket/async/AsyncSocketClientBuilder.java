package it.auties.leap.socket.async;

import it.auties.leap.socket.SocketClientBuilder;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.applicationLayer.AsyncPlainSocketApplicationLayer;
import it.auties.leap.socket.async.applicationLayer.AsyncSecureSocketApplicationLayer;
import it.auties.leap.tls.TlsConfig;

import java.net.URI;
import java.util.Objects;

public sealed class AsyncSocketClientBuilder extends SocketClientBuilder {
    final SocketProtocol protocol;
    AsyncSocketTransportLayerFactory transportFactory;

    AsyncSocketClientBuilder(SocketProtocol protocol) {
        this.protocol = protocol;
    }

    public AsyncSocketClientBuilder transport(AsyncSocketTransportLayerFactory transportFactory) {
        this.transportFactory = Objects.requireNonNullElseGet(transportFactory, AsyncSocketTransportLayerFactory::forPlatform);
        return this;
    }

    public AsyncSocketClientBuilder.Secure secure(TlsConfig config) {
        return new Secure(protocol, config);
    }

    public AsyncSocketClientBuilder.Plain plain() {
        return new Plain(protocol);
    }

    public static final class Secure extends AsyncSocketClientBuilder {
        private final TlsConfig config;
        private AsyncSocketTunnelLayerFactory tunnelFactory;
        private URI proxy;
        Secure(SocketProtocol protocol, TlsConfig config) {
            super(protocol);
            this.tunnelFactory = AsyncSocketTunnelLayerFactory.direct();
            this.config = config;
        }

        public Secure tunnel(URI proxy) {
            if(proxy == null) {
                this.tunnelFactory = AsyncSocketTunnelLayerFactory.direct();
                this.proxy = null;
            }else {
                this.tunnelFactory = AsyncSocketTunnelLayerFactory.forProxy(proxy);
                this.proxy = proxy;
            }
            return this;
        }

        public Secure tunnel(AsyncSocketTunnelLayerFactory tunnelFactory) {
            this.tunnelFactory = tunnelFactory;
            return this;
        }

        public AsyncSocketClient build() {
            var transport = transportFactory.newTransport(protocol);
            var application = new AsyncSecureSocketApplicationLayer(transport, config);
            var tunnel = tunnelFactory.newTunnel(application, proxy);
            return new AsyncSocketClient(application, tunnel);
        }
    }

    public static final class Plain extends AsyncSocketClientBuilder {
        private AsyncSocketTunnelLayerFactory tunnelFactory;
        private URI proxy;
        Plain(SocketProtocol protocol) {
            super(protocol);
            this.tunnelFactory = AsyncSocketTunnelLayerFactory.direct();
        }

        public Plain tunnel(URI proxy) {
            if(proxy == null) {
                this.tunnelFactory = AsyncSocketTunnelLayerFactory.direct();
                this.proxy = null;
            }else {
                this.tunnelFactory = AsyncSocketTunnelLayerFactory.forProxy(proxy);
                this.proxy = proxy;
            }
            return this;
        }

        public Plain tunnel(AsyncSocketTunnelLayerFactory tunnelFactory) {
            this.tunnelFactory = tunnelFactory;
            return this;
        }

        public AsyncSocketClient build() {
            var transport = transportFactory.newTransport(protocol);
            var application = new AsyncPlainSocketApplicationLayer(transport);
            var tunnel = tunnelFactory.newTunnel(application, proxy);
            return new AsyncSocketClient(application, tunnel);
        }
    }
}
