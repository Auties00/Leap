package it.auties.leap.socket.tunnel;

import it.auties.leap.http.HttpResponse;
import it.auties.leap.http.decoder.HttpDecoder;
import it.auties.leap.http.decoder.HttpResult;
import it.auties.leap.socket.security.SocketSecurityLayer;
import it.auties.leap.socket.transmission.SocketTransmissionLayer;

import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

final class HttpTunnelLayer extends SocketTunnelLayer {
    private static final int OK_STATUS_CODE = 200;

    HttpTunnelLayer(SocketTransmissionLayer<?> channel, SocketSecurityLayer securityLayer, URI proxy) {
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

                transmissionLayer.setAddress(address);
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
