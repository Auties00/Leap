package it.auties.leap.socket;

import it.auties.leap.http.decoder.HttpDecodable;
import it.auties.leap.socket.implementation.SocketImplementation;
import it.auties.leap.socket.implementation.bridge.LinuxImplementation;
import it.auties.leap.socket.implementation.bridge.UnixImplementation;
import it.auties.leap.socket.implementation.bridge.WinImplementation;
import it.auties.leap.socket.transport.SocketTransport;
import it.auties.leap.socket.transport.implementation.PlainTransport;
import it.auties.leap.socket.transport.implementation.SecureTransport;
import it.auties.leap.socket.tunnel.SocketTunnel;
import it.auties.leap.socket.tunnel.implementation.DirectTunnel;
import it.auties.leap.socket.tunnel.implementation.HTTPTunnel;
import it.auties.leap.socket.tunnel.implementation.SOCKSTunnel;
import it.auties.leap.tls.TlsEngine;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

@SuppressWarnings("unused")
public final class SocketClient implements HttpDecodable, AutoCloseable {
    private final SocketImplementation implementation;
    private final SocketTunnel tunnelLayer;
    private final SocketTransport securityLayer;
    private SocketClient(SocketImplementation implementation, SocketTunnel tunnelLayer, SocketTransport securityLayer) {
        this.implementation = implementation;
        this.tunnelLayer = tunnelLayer;
        this.securityLayer = securityLayer;
    }

    public static Builder builder() {
        return Builder.INSTANCE;
    }

    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return tunnelLayer.connect(address)
                .thenComposeAsync(_ -> securityLayer.handshake())
                .exceptionallyComposeAsync(error -> {
                    closeSilently();
                    return CompletableFuture.failedFuture(error);
                });
    }

    private void closeSilently() {
        try {
            close();
        }catch (Throwable ignored) {

        }
    }

    @Override
    public void close() throws IOException {
        implementation.close();
    }

    public boolean isConnected() {
        return implementation.isConnected();
    }

    public Optional<InetSocketAddress> remoteSocketAddress() {
        return implementation.remoteAddress();
    }

    public <V> SocketClient setOption(SocketOption<V> option, V value) {
        implementation.setOption(option, value);
        return this;
    }

    public <V> V getOption(SocketOption<V> option) {
        return implementation.getOption(option);
    }

    public CompletableFuture<Void> write(byte[] data) {
        return write(data, 0, data.length);
    }

    public CompletableFuture<Void> write(byte[] data, int offset, int length) {
        return write(ByteBuffer.wrap(data, offset, length));
    }

    public CompletableFuture<Void> write(ByteBuffer buffer) {
        return securityLayer.write(buffer);
    }

    @Override
    public CompletableFuture<ByteBuffer> read() {
        return securityLayer.read();
    }

    public CompletableFuture<ByteBuffer> read(ByteBuffer buffer) {
        return securityLayer.read(buffer, true);
    }

    @Override
    public CompletableFuture<ByteBuffer> readFully(int length) {
        return securityLayer.readFully(length);
    }

    private CompletableFuture<ByteBuffer> readFully(ByteBuffer buffer) {
        return securityLayer.readFully(buffer);
    }
    
    public static sealed class Builder {
        private static final Builder INSTANCE = new Builder();
        private Builder() {

        }

        public Security async(SocketProtocol protocol) {
            return switch (protocol) {
                case TCP -> Security.TCP_ASYNC;
                case UDP -> Security.UDP_ASYNC;
            };
        }

        public Security blocking(SocketProtocol protocol) {
            return switch (protocol) {
                case TCP -> Security.TCP_BLOCKING;
                case UDP -> Security.UDP_BLOCKING;
            };
        }

        public Security custom(SocketImplementation platform) {
            return new Security(new PlatformValue.Custom(platform));
        }
        
        public static final class Security extends Builder {
            private static final Security TCP_ASYNC = new Security(PlatformValue.Async.TCP);
            private static final Security UDP_ASYNC = new Security(PlatformValue.Async.UDP);
            private static final Security TCP_BLOCKING = new Security(PlatformValue.Blocking.TCP);
            private static final Security UDP_BLOCKING = new Security(PlatformValue.Blocking.UDP);

            private final PlatformValue platform;
            
            private Security(PlatformValue platform) {
                this.platform = platform;
            }
            
            public TunnelOrFinish plain() {
                return switch (platform) {
                    case PlatformValue.Async async -> switch (async.protocol()) {
                        case TCP -> TunnelOrFinish.TCP_ASYNC_PLAIN;
                        case UDP -> TunnelOrFinish.UDP_ASYNC_PLAIN;
                    };
                    case PlatformValue.Blocking blocking -> switch (blocking.protocol()) {
                        case TCP -> TunnelOrFinish.TCP_BLOCKING_PLAIN;
                        case UDP -> TunnelOrFinish.UDP_BLOCKING_PLAIN;
                    };
                    case PlatformValue.Custom custom -> new TunnelOrFinish(custom, SecurityValue.Plain.INSTANCE);
                };
            }

            public TunnelOrFinish secure(TlsEngine.Config config) {
                return new TunnelOrFinish(platform, new SecurityValue.Secure(config));
            }

            public TunnelOrFinish custom(SocketTransport security) {
                return new TunnelOrFinish(platform, new SecurityValue.Custom(security));
            }
        }

        public static final class TunnelOrFinish extends Finish {
            private static final TunnelOrFinish TCP_ASYNC_PLAIN = new TunnelOrFinish(PlatformValue.Async.TCP, SecurityValue.Plain.INSTANCE);
            private static final TunnelOrFinish TCP_BLOCKING_PLAIN = new TunnelOrFinish(PlatformValue.Async.TCP, SecurityValue.Plain.INSTANCE);

            private static final TunnelOrFinish UDP_ASYNC_PLAIN = new TunnelOrFinish(PlatformValue.Async.UDP, SecurityValue.Plain.INSTANCE);
            private static final TunnelOrFinish UDP_BLOCKING_PLAIN = new TunnelOrFinish(PlatformValue.Async.UDP, SecurityValue.Plain.INSTANCE);

            TunnelOrFinish(PlatformValue platform, SecurityValue security) {
                super(platform, security, TunnelValue.Direct.INSTANCE);
            }

            public Finish proxy(URI proxy) {
                if(proxy == null) {
                    return this;
                }

                return new Finish(platform, security, new TunnelValue.Proxy(proxy));
            }

            public Finish custom(SocketTunnel tunnel) {
                return new Finish(platform, security, new TunnelValue.Custom(tunnel));
            }
        }

        public static sealed class Finish extends Builder {
            final PlatformValue platform;
            final SecurityValue security;
            final TunnelValue tunnel;

            Finish(PlatformValue platform, SecurityValue security, TunnelValue tunnel) {
                this.platform = platform;
                this.security = security;
                this.tunnel = tunnel;
            }

            @SuppressWarnings("resource")
            public SocketClient build() {
                var os = System.getProperty("os.name").toLowerCase();
                var socketPlatform = switch (platform) {
                    case PlatformValue.Async async -> createAsyncPlatform(async.protocol());
                    case PlatformValue.Blocking blocking -> createBlockingPlatform(blocking.protocol());
                    case PlatformValue.Custom custom -> custom.value();
                };
                var socketSecurity = switch (security) {
                    case SecurityValue.Custom custom -> custom.security();
                    case SecurityValue.Plain _ -> new PlainTransport(socketPlatform);
                    case SecurityValue.Secure secure -> new SecureTransport(socketPlatform, secure.config());
                };
                var socketTunnel = switch (tunnel) {
                    case TunnelValue.Custom custom -> custom.tunnel();
                    case TunnelValue.Direct direct -> new DirectTunnel(socketPlatform);
                    case TunnelValue.Proxy proxy -> {
                        var scheme = normalizeScheme(proxy);
                        yield switch (scheme) {
                            case "http", "https" -> new HTTPTunnel(socketPlatform, socketSecurity, proxy.value());
                            case "socks5", "socks5h" -> new SOCKSTunnel(socketPlatform, socketSecurity, proxy.value());
                            case null, default -> throw new IllegalStateException("Unexpected scheme: " + scheme);
                        };
                    }
                };
                return new SocketClient(socketPlatform, socketTunnel, socketSecurity);
            }

            private SocketImplementation createAsyncPlatform(SocketProtocol protocol) {
                var os = System.getProperty("os.name").toLowerCase();
                if(os.contains("win")) {
                    return new WinImplementation(protocol);
                }else if(os.contains("nix") || os.contains("nux") || os.contains("aix")) {
                    return new LinuxImplementation(protocol);
                }else if(os.contains("mac")) {
                    return new UnixImplementation(protocol);
                }else {
                    throw new IllegalArgumentException("Unsupported platform: " + os);
                }
            }

            private SocketImplementation createBlockingPlatform(SocketProtocol protocol) {
                throw new UnsupportedOperationException();
            }

            private String normalizeScheme(TunnelValue.Proxy proxy) {
                var scheme = proxy.value().getScheme();
                return scheme != null ? scheme.toLowerCase() : null;
            }
        }

        private sealed interface PlatformValue {
            record Async(SocketProtocol protocol) implements PlatformValue {
                private static final Async TCP = new Async(SocketProtocol.TCP);
                private static final Async UDP = new Async(SocketProtocol.UDP);
            }

            record Blocking(SocketProtocol protocol) implements PlatformValue {
                private static final Blocking TCP = new Blocking(SocketProtocol.TCP);
                private static final Blocking UDP = new Blocking(SocketProtocol.UDP);
            }

            record Custom(SocketImplementation value) implements PlatformValue {

            }
        }

        private sealed interface SecurityValue {
            final class Plain implements SecurityValue {
                private static final Plain INSTANCE = new Plain();
            }

            record Secure(TlsEngine.Config config) implements SecurityValue {

            }

            record Custom(SocketTransport security) implements SecurityValue {

            }
        }

        private sealed interface TunnelValue {
            final class Direct implements TunnelValue {
                private static final Direct INSTANCE = new Direct();
            }

            record Proxy(URI value) implements TunnelValue {

            }

            record Custom(SocketTunnel tunnel) implements TunnelValue {

            }
        }
    }
}
