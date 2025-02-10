package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketClientBuilder;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.blocking.applicationLayer.BlockingPlainApplicationLayer;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSecureApplicationLayer;
import it.auties.leap.tls.TlsConfig;

import java.net.URI;
import java.util.Objects;

public sealed class BlockingSocketClientBuilder extends SocketClientBuilder {
    final SocketProtocol protocol;
    BlockingSocketTransportLayerFactory transportFactory;

    BlockingSocketClientBuilder(SocketProtocol protocol) {
        this.protocol = protocol;
    }

    public BlockingSocketClientBuilder transport(BlockingSocketTransportLayerFactory transportFactory) {
        this.transportFactory = Objects.requireNonNullElseGet(transportFactory, BlockingSocketTransportLayerFactory::forPlatform);
        return this;
    }

    public BlockingSocketClientBuilder secure(TlsConfig config) {
        return new Secure(protocol, config);
    }

    public BlockingSocketClientBuilder plain() {
        return new Plain(protocol);
    }

    public static final class Secure extends BlockingSocketClientBuilder {
        private final TlsConfig config;
        private BlockingSocketTunnelLayerFactory tunnelFactory;
        private URI proxy;
        Secure(SocketProtocol protocol, TlsConfig config) {
            super(protocol);
            this.tunnelFactory = BlockingSocketTunnelLayerFactory.direct();
            this.config = config;
        }

        public Secure tunnel(URI proxy) {
            if(proxy == null) {
                this.tunnelFactory = BlockingSocketTunnelLayerFactory.direct();
                this.proxy = null;
            }else {
                this.tunnelFactory = BlockingSocketTunnelLayerFactory.forProxy(proxy);
                this.proxy = proxy;
            }
            return this;
        }

        public Secure tunnel(BlockingSocketTunnelLayerFactory tunnelFactory) {
            this.tunnelFactory = tunnelFactory;
            return this;
        }

        public BlockingSocketClient build() {
            var transport = transportFactory.newTransport(protocol);
            var application = new BlockingSecureApplicationLayer(transport, config);
            var tunnel = tunnelFactory.newTunnel(application, proxy);
            return new BlockingSocketClient(application, tunnel);
        }
    }

    public static final class Plain extends BlockingSocketClientBuilder {
        private BlockingSocketTunnelLayerFactory tunnelFactory;
        private URI proxy;
        Plain(SocketProtocol protocol) {
            super(protocol);
            this.tunnelFactory = BlockingSocketTunnelLayerFactory.direct();
        }

        public Plain tunnel(URI proxy) {
            if(proxy == null) {
                this.tunnelFactory = BlockingSocketTunnelLayerFactory.direct();
                this.proxy = null;
            }else {
                this.tunnelFactory = BlockingSocketTunnelLayerFactory.forProxy(proxy);
                this.proxy = proxy;
            }
            return this;
        }

        public Plain tunnel(BlockingSocketTunnelLayerFactory tunnelFactory) {
            this.tunnelFactory = tunnelFactory;
            return this;
        }

        public BlockingSocketClient build() {
            var transport = transportFactory.newTransport(protocol);
            var application = new BlockingPlainApplicationLayer(transport);
            var tunnel = tunnelFactory.newTunnel(application, proxy);
            return new BlockingSocketClient(application, tunnel);
        }
    }
}
