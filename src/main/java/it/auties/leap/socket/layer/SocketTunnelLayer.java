package it.auties.leap.socket.layer;

import it.auties.leap.http.HttpResponse;
import it.auties.leap.http.decoder.HttpDecoder;
import it.auties.leap.http.decoder.HttpResult;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public sealed abstract class SocketTunnelLayer {
    final SocketTransmissionLayer<?> transmissionLayer;
    final SocketSecurityLayer securityLayer;
    final URI proxy;

    private SocketTunnelLayer(SocketTransmissionLayer<?> transmissionLayer, SocketSecurityLayer securityLayer, URI proxy) {
        this.transmissionLayer = transmissionLayer;
        this.securityLayer = securityLayer;
        this.proxy = proxy;
    }

    public static SocketTunnelLayer of(SocketTransmissionLayer<?> channel, SocketSecurityLayer securityLayer, URI proxy) {
        return switch (toProxy(proxy).type()) {
            case DIRECT -> new DirectProxy(channel);
            case HTTP -> new HttpProxy(channel, securityLayer, proxy);
            case SOCKS -> new SocksProxy(channel, securityLayer, proxy);
        };
    }

    private static Proxy toProxy(URI uri) {
        if (uri == null) {
            return Proxy.NO_PROXY;
        }

        var scheme = Objects.requireNonNull(uri.getScheme(), "Invalid proxy, expected a scheme: %s".formatted(uri));
        var host = Objects.requireNonNull(uri.getHost(), "Invalid proxy, expected a host: %s".formatted(uri));
        var port = getDefaultPort(scheme, uri.getPort()).orElseThrow(() -> new NullPointerException("Invalid proxy, expected a port: %s".formatted(uri)));
        return switch (scheme.toLowerCase()) {
            case "http", "https" -> new Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(host, port));
            case "socks5", "socks5h" -> new Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(host, port));
            default -> throw new IllegalStateException("Unexpected scheme: " + scheme);
        };
    }

    private static OptionalInt getDefaultPort(String scheme, int port) {
        return port != -1 ? OptionalInt.of(port) : switch (scheme.toLowerCase()) {
            case "http" -> OptionalInt.of(80);
            case "https" -> OptionalInt.of(443);
            default -> OptionalInt.empty();
        };
    }

    public abstract CompletableFuture<Void> connect(InetSocketAddress address);

    private static final class DirectProxy extends SocketTunnelLayer {
        private DirectProxy(SocketTransmissionLayer<?> channel) {
            super(channel, null, null);
        }

        @Override
        public CompletableFuture<Void> connect(InetSocketAddress address) {
            return transmissionLayer.connect(address);
        }
    }

    private static final class HttpProxy extends SocketTunnelLayer {
        private static final int OK_STATUS_CODE = 200;

        private HttpProxy(SocketTransmissionLayer<?> channel, SocketSecurityLayer securityLayer, URI proxy) {
            super(channel, securityLayer, proxy);
        }

        @Override
        public CompletableFuture<Void> connect(InetSocketAddress address) {
            return transmissionLayer.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()))
                    .thenCompose(_ -> sendAuthentication(address))
                    .thenCompose(_ -> readAuthenticationResponse(address));
        }

        private CompletableFuture<Void> readAuthenticationResponse(InetSocketAddress address) {
            var decoder = new HttpDecoder(securityLayer);
            return decoder.readResponse(null, HttpResponse.Converter.ofString())
                    .thenCompose(result -> onAuthenticationResponse(result, address))
                    .exceptionallyCompose(error -> CompletableFuture.failedFuture(new SocketException("HTTP : Cannot read authentication response", error)));
        }

        private CompletionStage<Void> onAuthenticationResponse(HttpResult<String> result, InetSocketAddress address) {
            return switch (result) {
                case HttpResult.Response<String> response -> {
                    if (response.statusCode() != OK_STATUS_CODE) {
                        yield CompletableFuture.failedFuture(new SocketException("HTTP : Cannot connect to proxy, status code " + response.statusCode()));
                    }

                    transmissionLayer.address = address;
                    yield CompletableFuture.completedFuture((Void) null);
                }

                case HttpResult.Redirect<String> _ ->
                        CompletableFuture.failedFuture(new SocketException("HTTP : Invalid redirect while connecting to proxy"));
            };
        }

        private CompletableFuture<Void> sendAuthentication(InetSocketAddress endpoint) {
            var builder = new StringBuilder();
            builder.append("CONNECT ")
                    .append(endpoint.getHostName())
                    .append(":")
                    .append(endpoint.getPort())
                    .append(" HTTP/1.1\r\n");
            builder.append("host: ")
                    .append(endpoint.getHostName())
                    .append("\r\n");
            var authInfo = proxy.getUserInfo();
            if (authInfo != null) {
                builder.append("proxy-authorization: Basic ")
                        .append(Base64.getEncoder().encodeToString(authInfo.getBytes()))
                        .append("\r\n");
            }
            builder.append("\r\n");
            return securityLayer.write(ByteBuffer.wrap(builder.toString().getBytes()));
        }
    }

    private static final class SocksProxy extends SocketTunnelLayer {
        private static final byte VERSION_5 = 5;

        private static final int NO_AUTH = 0;
        private static final int USER_PASSW = 2;
        private static final int NO_METHODS = -1;

        private static final int CONNECT = 1;

        private static final int IPV4 = 1;
        private static final int DOMAIN_NAME = 3;
        private static final int IPV6 = 4;

        private static final int REQUEST_OK = 0;
        private static final int GENERAL_FAILURE = 1;
        private static final int NOT_ALLOWED = 2;
        private static final int NET_UNREACHABLE = 3;
        private static final int HOST_UNREACHABLE = 4;
        private static final int CONN_REFUSED = 5;
        private static final int TTL_EXPIRED = 6;
        private static final int CMD_NOT_SUPPORTED = 7;
        private static final int ADDR_TYPE_NOT_SUP = 8;

        private SocksProxy(SocketTransmissionLayer<?> channel, SocketSecurityLayer securityLayer, URI proxy) {
            super(channel, securityLayer, proxy);
        }


        @Override
        public CompletableFuture<Void> connect(InetSocketAddress address) {
            return transmissionLayer.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()))
                    .thenCompose(_ -> sendAuthenticationRequest())
                    .thenCompose(this::sendAuthenticationData)
                    .thenCompose(connectionResponse -> sendConnectionData(connectionResponse, address));
        }

        private CompletableFuture<ByteBuffer> sendAuthenticationRequest() {
            var connectionPayload = new ByteArrayOutputStream();
            connectionPayload.write(VERSION_5);
            connectionPayload.write(2);
            connectionPayload.write(NO_AUTH);
            connectionPayload.write(USER_PASSW);
            return securityLayer.write(ByteBuffer.wrap(connectionPayload.toByteArray()))
                    .thenCompose(_ -> readOrThrow(2, "Cannot read authentication request response"));
        }

        private CompletionStage<ByteBuffer> sendAuthenticationData(ByteBuffer response) {
            var socksVersion = response.get();
            if (socksVersion != VERSION_5) {
                return CompletableFuture.failedFuture(new SocketException("SOCKS : Invalid version"));
            }

            var method = response.get();
            if (method == NO_METHODS) {
                return CompletableFuture.failedFuture(new SocketException("SOCKS : No acceptable methods"));
            }

            if (method == NO_AUTH) {
                return CompletableFuture.completedFuture(null);
            }

            if (method != USER_PASSW) {
                return CompletableFuture.failedFuture(new SocketException("SOCKS : authentication failed"));
            }

            var userInfo = parseUserInfo(proxy.getUserInfo());
            if (userInfo.isEmpty()) {
                return CompletableFuture.failedFuture(new SocketException("SOCKS : invalid authentication data"));
            }

            var outputStream = new ByteArrayOutputStream();
            outputStream.write(1);
            outputStream.write(userInfo.get().username().length());
            outputStream.writeBytes(userInfo.get().username().getBytes(StandardCharsets.ISO_8859_1));
            if (userInfo.get().password() != null) {
                outputStream.write(userInfo.get().password().length());
                outputStream.writeBytes(userInfo.get().password().getBytes(StandardCharsets.ISO_8859_1));
            } else {
                outputStream.write(0);
            }
            return securityLayer.write(ByteBuffer.wrap(outputStream.toByteArray()))
                    .thenCompose(_ -> readOrThrow(2, "Cannot read authentication data response"));
        }

        private CompletableFuture<Void> sendConnectionData(ByteBuffer connectionResponse, InetSocketAddress address) {
            if (connectionResponse != null && connectionResponse.get(1) != 0) {
                return CompletableFuture.failedFuture(new SocketException("SOCKS : authentication failed"));
            }

            var outputStream = new ByteArrayOutputStream();
            outputStream.write(VERSION_5);
            outputStream.write(CONNECT);
            outputStream.write(0);
            outputStream.write(DOMAIN_NAME);
            outputStream.write(address.getHostName().length());
            outputStream.writeBytes(address.getHostName().getBytes(StandardCharsets.ISO_8859_1));
            outputStream.write((address.getPort() >> 8) & 0xff);
            outputStream.write((address.getPort()) & 0xff);
            return securityLayer.write(ByteBuffer.wrap(outputStream.toByteArray()))
                    .thenCompose(_ -> readOrThrow(4, "Cannot read connection data response"))
                    .thenCompose(authenticationType -> onConnected(authenticationType, address));
        }

        private static Optional<UserInfo> parseUserInfo(String userInfo) {
            if (userInfo == null || userInfo.isEmpty()) {
                return Optional.empty();
            }

            var data = userInfo.split(":", 2);
            if (data.length > 2) {
                return Optional.empty();
            }

            return Optional.of(new UserInfo(data[0], data.length == 2 ? data[1] : null));
        }

        private record UserInfo(String username, String password) {

        }

        private CompletableFuture<Void> onConnected(ByteBuffer authenticationResponse, InetSocketAddress address) {
            if (authenticationResponse.limit() < 2) {
                return CompletableFuture.failedFuture(new SocketException("SOCKS malformed response"));
            }

            return switch (authenticationResponse.get(1)) {
                case REQUEST_OK ->
                        onConnected(authenticationResponse.get(3), address);
                case GENERAL_FAILURE ->
                        CompletableFuture.failedFuture(new SocketException("SOCKS server general failure"));
                case NOT_ALLOWED ->
                        CompletableFuture.failedFuture(new SocketException("SOCKS: Connection not allowed by ruleset"));
                case NET_UNREACHABLE ->
                        CompletableFuture.failedFuture(new SocketException("SOCKS: Network unreachable"));
                case HOST_UNREACHABLE ->
                        CompletableFuture.failedFuture(new SocketException("SOCKS: Host unreachable"));
                case CONN_REFUSED ->
                        CompletableFuture.failedFuture(new SocketException("SOCKS: Connection refused"));
                case TTL_EXPIRED ->
                        CompletableFuture.failedFuture(new SocketException("SOCKS: TTL expired"));
                case CMD_NOT_SUPPORTED ->
                        CompletableFuture.failedFuture(new SocketException("SOCKS: Command not supported"));
                case ADDR_TYPE_NOT_SUP ->
                        CompletableFuture.failedFuture(new SocketException("SOCKS: address type not supported"));
                default ->
                        CompletableFuture.failedFuture(new SocketException("SOCKS: unhandled error"));
            };
        }

        private CompletableFuture<Void> onConnected(byte authenticationType, InetSocketAddress address) {
            return switch (authenticationType) {
                case IPV4 -> readOrThrow(4, "Cannot read IPV4 address")
                        .thenCompose(_ -> readOrThrow(2, "Cannot read IPV4 port"))
                        .thenRun(() -> transmissionLayer.address = address);
                case IPV6 -> readOrThrow(16, "Cannot read IPV6 address")
                        .thenCompose(_ -> readOrThrow(2, "Cannot read IPV6 port"))
                        .thenRun(() -> transmissionLayer.address = address);
                case DOMAIN_NAME -> readOrThrow(1, "Cannot read domain name")
                        .thenCompose(domainLengthBuffer -> readOrThrow(Byte.toUnsignedInt(domainLengthBuffer.get()), "Cannot read domain hostname"))
                        .thenCompose(_ -> readOrThrow(2, "Cannot read domain port"))
                        .thenRun(() -> transmissionLayer.address = address);
                default ->
                        CompletableFuture.failedFuture(new SocketException("Reply from SOCKS server contains wrong code"));
            };
        }

        private CompletableFuture<ByteBuffer> readOrThrow(int length, String errorMessage) {
            var buffer = ByteBuffer.allocate(length);
            return securityLayer.readFully(buffer)
                    .exceptionallyCompose(error -> CompletableFuture.failedFuture(new SocketException(errorMessage, error)));
        }
    }
}
