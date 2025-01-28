package it.auties.leap.socket;

import it.auties.leap.http.decoder.HttpDecodable;
import it.auties.leap.socket.platform.SocketPlatform;
import it.auties.leap.socket.platform.implementation.LinuxPlatform;
import it.auties.leap.socket.platform.implementation.UnixPlatform;
import it.auties.leap.socket.platform.implementation.WinPlatform;
import it.auties.leap.socket.security.SocketSecurity;
import it.auties.leap.socket.security.implementation.PlainSocket;
import it.auties.leap.socket.security.implementation.SecureSocket;
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
    private final SocketPlatform<?> transmissionLayer;
    private final SocketTunnel tunnelLayer;
    private final SocketSecurity securityLayer;
    private SocketClient(SocketPlatform<?> transmissionLayer, SocketTunnel tunnelLayer, SocketSecurity securityLayer) {
        this.transmissionLayer = transmissionLayer;
        this.tunnelLayer = tunnelLayer;
        this.securityLayer = securityLayer;
    }

    public CompletableFuture<Void> connect(InetSocketAddress address) {
        if(isConnected()) {
            return CompletableFuture.completedFuture(null);
        }

        return tunnelLayer.connect(address)
                .thenComposeAsync(ignored -> securityLayer.handshake())
                .exceptionallyComposeAsync(error -> {
                    try {
                        close();
                    }catch (Throwable ignored) {

                    }

                    return CompletableFuture.failedFuture(error);
                });
    }
    
    @Override
    public void close() throws IOException {
        transmissionLayer.close();
    }

    public boolean isConnected() {
        return transmissionLayer.isConnected();
    }

    public Optional<InetSocketAddress> remoteSocketAddress() {
        return transmissionLayer.address();
    }

    public <V> void setOption(SocketOption<V> option, V value) {
        transmissionLayer.setOption(option, value);
    }

    public <V> V getOption(SocketOption<V> option) {
        return transmissionLayer.getOption(option);
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
    
    public static final class Builder {
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

        public Security custom(SocketPlatform<?> platform) {
            return new Security(new PlatformValue.Custom(platform));
        }
        
        public static final class Security {
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
                return switch (platform) {
                    case PlatformValue.Async async -> switch (async.protocol()) {
                        case TCP -> TunnelOrFinish.TCP_ASYNC_PLAIN;
                        case UDP -> TunnelOrFinish.UDP_ASYNC_PLAIN;
                    };
                    case PlatformValue.Blocking blocking -> switch (blocking.protocol()) {
                        case TCP -> TunnelOrFinish.TCP_BLOCKING_PLAIN;
                        case UDP -> TunnelOrFinish.UDP_BLOCKING_PLAIN;
                    };
                    case PlatformValue.Custom custom -> new TunnelOrFinish(custom, SecurityValue.Secure.INSTANCE);
                };
            }

            public TunnelOrFinish security(SocketSecurity security) {
                return new TunnelOrFinish(platform, new SecurityValue.Custom(security));
            }
        }

        public static final class TunnelOrFinish extends Finish {
            private static final TunnelOrFinish TCP_ASYNC_PLAIN = new TunnelOrFinish(PlatformValue.Async.TCP, SecurityValue.Plain.INSTANCE);
            private static final TunnelOrFinish TCP_ASYNC_SECURE = new TunnelOrFinish(PlatformValue.Async.TCP, SecurityValue.Secure.INSTANCE);
            private static final TunnelOrFinish TCP_BLOCKING_PLAIN = new TunnelOrFinish(PlatformValue.Async.TCP, SecurityValue.Plain.INSTANCE);
            private static final TunnelOrFinish TCP_BLOCKING_SECURE = new TunnelOrFinish(PlatformValue.Async.TCP, SecurityValue.Secure.INSTANCE);

            private static final TunnelOrFinish UDP_ASYNC_PLAIN = new TunnelOrFinish(PlatformValue.Async.UDP, SecurityValue.Plain.INSTANCE);
            private static final TunnelOrFinish UDP_ASYNC_SECURE = new TunnelOrFinish(PlatformValue.Async.UDP, SecurityValue.Secure.INSTANCE);
            private static final TunnelOrFinish UDP_BLOCKING_PLAIN = new TunnelOrFinish(PlatformValue.Async.UDP, SecurityValue.Plain.INSTANCE);
            private static final TunnelOrFinish UDP_BLOCKING_SECURE = new TunnelOrFinish(PlatformValue.Async.UDP, SecurityValue.Secure.INSTANCE);

            TunnelOrFinish(PlatformValue platform, SecurityValue security) {
                super(platform, security, TunnelValue.Direct.INSTANCE);
            }


            public Finish proxy(URI proxy) {
                return new Finish(platform, security, new TunnelValue.Proxy(proxy));
            }

            public Finish custom(SocketTunnel tunnel) {
                return new Finish(platform, security, new TunnelValue.Custom(tunnel));
            }
        }

        public static sealed class Finish {
            final PlatformValue platform;
            final SecurityValue security;
            final TunnelValue tunnel;

            Finish(PlatformValue platform, SecurityValue security, TunnelValue tunnel) {
                this.platform = platform;
                this.security = security;
                this.tunnel = tunnel;
            }
            
            public SocketClient build() {
                var socketPlatform = switch (platform) {
                    case PlatformValue.Async async -> createAsyncPlatform(async.protocol());
                    case PlatformValue.Blocking blocking -> createBlockingPlatform(blocking.protocol());
                    case PlatformValue.Custom custom -> custom.value();
                };
                var socketSecurity = switch (security) {
                    case SecurityValue.Custom custom -> custom.security();
                    case SecurityValue.Plain _ -> new PlainSocket(socketPlatform);
                    case SecurityValue.Secure secure -> new SecureSocket(socketPlatform, secure.config());
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

            private SocketPlatform<?> createAsyncPlatform(SocketProtocol protocol) {
                var os = System.getProperty("os.name").toLowerCase();
                if(os.contains("win")) {
                    return new WinPlatform(protocol);
                }else if(os.contains("nix") || os.contains("nux") || os.contains("aix")) {
                    return new LinuxPlatform(protocol);
                }else if(os.contains("mac")) {
                    return new UnixPlatform(protocol);
                }else {
                    throw new IllegalArgumentException("Unsupported platform: " + os);
                }
            }

            private SocketPlatform<?> createBlockingPlatform(SocketProtocol protocol) {
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

            record Custom(SocketPlatform<?> value) implements PlatformValue {

            }
        }

        private sealed interface SecurityValue {
            final class Plain implements SecurityValue {
                private static final Plain INSTANCE = new Plain();
            }

            record Secure(TlsEngine.Config config) implements SecurityValue {
                private static final Secure INSTANCE = new Secure(TlsEngine.Config.defaults());
            }

            record Custom(SocketSecurity security) implements SecurityValue {

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
