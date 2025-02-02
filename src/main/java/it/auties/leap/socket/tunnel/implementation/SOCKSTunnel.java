package it.auties.leap.socket.tunnel.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.implementation.SocketImplementation;
import it.auties.leap.socket.transport.SocketTransport;
import it.auties.leap.socket.tunnel.SocketTunnel;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public final class SOCKSTunnel extends SocketTunnel {
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

    public SOCKSTunnel(SocketImplementation channel, SocketTransport securityLayer, URI proxy) {
        super(channel, securityLayer, proxy);
    }


    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return implementation.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()))
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
            case REQUEST_OK -> onConnected(authenticationResponse.get(3), address);
            case GENERAL_FAILURE -> CompletableFuture.failedFuture(new SocketException("SOCKS server general failure"));
            case NOT_ALLOWED ->
                    CompletableFuture.failedFuture(new SocketException("SOCKS: Connection not allowed by ruleset"));
            case NET_UNREACHABLE -> CompletableFuture.failedFuture(new SocketException("SOCKS: Network unreachable"));
            case HOST_UNREACHABLE -> CompletableFuture.failedFuture(new SocketException("SOCKS: Host unreachable"));
            case CONN_REFUSED -> CompletableFuture.failedFuture(new SocketException("SOCKS: Connection refused"));
            case TTL_EXPIRED -> CompletableFuture.failedFuture(new SocketException("SOCKS: TTL expired"));
            case CMD_NOT_SUPPORTED ->
                    CompletableFuture.failedFuture(new SocketException("SOCKS: Command not supported"));
            case ADDR_TYPE_NOT_SUP ->
                    CompletableFuture.failedFuture(new SocketException("SOCKS: address type not supported"));
            default -> CompletableFuture.failedFuture(new SocketException("SOCKS: unhandled error"));
        };
    }

    private CompletableFuture<Void> onConnected(byte authenticationType, InetSocketAddress address) {
        return switch (authenticationType) {
            case IPV4 -> readOrThrow(4, "Cannot read IPV4 address")
                    .thenCompose(_ -> readOrThrow(2, "Cannot read IPV4 port"))
                    .thenRun(() -> implementation.setRemoteAddress(address));
            case IPV6 -> readOrThrow(16, "Cannot read IPV6 address")
                    .thenCompose(_ -> readOrThrow(2, "Cannot read IPV6 port"))
                    .thenRun(() -> implementation.setRemoteAddress(address));
            case DOMAIN_NAME -> readOrThrow(1, "Cannot read domain name")
                    .thenCompose(domainLengthBuffer -> readOrThrow(Byte.toUnsignedInt(domainLengthBuffer.get()), "Cannot read domain hostname"))
                    .thenCompose(_ -> readOrThrow(2, "Cannot read domain port"))
                    .thenRun(() -> implementation.setRemoteAddress(address));
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
