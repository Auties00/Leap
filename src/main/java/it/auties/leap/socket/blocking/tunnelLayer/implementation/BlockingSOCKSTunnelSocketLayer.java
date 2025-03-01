package it.auties.leap.socket.blocking.tunnelLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayerFactory;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public final class BlockingSOCKSTunnelSocketLayer extends BlockingSocketTunnelLayer {
    private static final BlockingSocketTunnelLayerFactory FACTORY = BlockingHTTPTunnelSocketLayer::new;

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

    private final URI proxy;
    public BlockingSOCKSTunnelSocketLayer(BlockingSocketApplicationLayer applicationLayer, URI proxy) {
        super(applicationLayer);
        this.proxy = proxy;
    }

    public static BlockingSocketTunnelLayerFactory factory() {
        return FACTORY;
    }

    @Override
    public void connect(InetSocketAddress address) {
        applicationLayer.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()));
        var authenticationResponse = sendAuthenticationRequest();
        var connectionResponse = sendAuthenticationData(authenticationResponse);
        sendConnectionData(connectionResponse, address);
    }

    private ByteBuffer sendAuthenticationRequest() {
        var connectionPayload = new ByteArrayOutputStream();
        connectionPayload.write(VERSION_5);
        connectionPayload.write(2);
        connectionPayload.write(NO_AUTH);
        connectionPayload.write(USER_PASSW);
        applicationLayer.write(ByteBuffer.wrap(connectionPayload.toByteArray()));
        return readOrThrow(2, "Cannot read authentication request response");
    }

    private ByteBuffer sendAuthenticationData(ByteBuffer response) {
        var socksVersion = response.get();
        if (socksVersion != VERSION_5) {
            throw new SocketException("SOCKS : Invalid version");
        }

        var method = response.get();
        if (method == NO_METHODS) {
            throw new SocketException("SOCKS : No acceptable methods");
        }

        if (method == NO_AUTH) {
            return null;
        }

        if (method != USER_PASSW) {
            throw new SocketException("SOCKS : authentication failed");
        }

        var userInfo = parseUserInfo(proxy.getUserInfo());
        if (userInfo.isEmpty()) {
            throw new SocketException("SOCKS : invalid authentication data");
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
        applicationLayer.write(ByteBuffer.wrap(outputStream.toByteArray()));
        return readOrThrow(2, "Cannot read authentication data response");
    }

    private void sendConnectionData(ByteBuffer connectionResponse, InetSocketAddress address) {
        if (connectionResponse != null && connectionResponse.get(1) != 0) {
            throw new SocketException("SOCKS : authentication failed");
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
        applicationLayer.write(ByteBuffer.wrap(outputStream.toByteArray()));
        var authenticationType = readOrThrow(4, "Cannot read connection data response");
        onConnected(authenticationType, address);
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

    private void onConnected(ByteBuffer authenticationResponse, InetSocketAddress address) {
        if (authenticationResponse.limit() < 2) {
            throw new SocketException("SOCKS malformed response");
        }

        switch (authenticationResponse.get(1)) {
            case REQUEST_OK -> onConnected(authenticationResponse.get(3), address);
            case GENERAL_FAILURE -> throw new SocketException("SOCKS server general failure");
            case NOT_ALLOWED -> throw new SocketException("SOCKS: Connection not allowed by ruleset");
            case NET_UNREACHABLE -> throw new SocketException("SOCKS: Network unreachable");
            case HOST_UNREACHABLE -> throw new SocketException("SOCKS: Host unreachable");
            case CONN_REFUSED -> throw new SocketException("SOCKS: Connection refused");
            case TTL_EXPIRED -> throw new SocketException("SOCKS: TTL expired");
            case CMD_NOT_SUPPORTED -> throw new SocketException("SOCKS: Command not supported");
            case ADDR_TYPE_NOT_SUP -> throw new SocketException("SOCKS: address type not supported");
            default -> throw new SocketException("SOCKS: unhandled error");
        }
    }

    private void onConnected(byte authenticationType, InetSocketAddress address) {
        switch (authenticationType) {
            case IPV4 -> {
                readOrThrow(4, "Cannot read IPV4 address");
                readOrThrow(2, "Cannot read IPV4 port");
                applicationLayer.setAddress(address);
            }
            case IPV6 -> {
                readOrThrow(16, "Cannot read IPV6 address");
                        readOrThrow(2, "Cannot read IPV6 port");
                  applicationLayer.setAddress(address);
            }
            case DOMAIN_NAME -> {
                var domainLengthBuffer = readOrThrow(1, "Cannot read domain name");
                readOrThrow(Byte.toUnsignedInt(domainLengthBuffer.get()), "Cannot read domain hostname");
                readOrThrow(2, "Cannot read domain port");
                applicationLayer.setAddress(address);
            }
              
            default -> throw new SocketException("Reply from SOCKS server contains wrong code");
        }
    }

    private ByteBuffer readOrThrow(int length, String errorMessage) {
        try {
            var buffer = ByteBuffer.allocate(length);
            applicationLayer.readFully(buffer);
            return buffer;
        }catch (Throwable error) {
            throw new SocketException(errorMessage, error);
        }
    }
}
