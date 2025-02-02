package it.auties.leap.socket.tunnel.implementation;

import it.auties.leap.http.HttpResponse;
import it.auties.leap.http.decoder.HttpDecoder;
import it.auties.leap.http.decoder.HttpResult;
import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.implementation.SocketImplementation;
import it.auties.leap.socket.transport.SocketTransport;
import it.auties.leap.socket.tunnel.SocketTunnel;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public final class HTTPTunnel extends SocketTunnel {
    private static final int OK_STATUS_CODE = 200;

    public HTTPTunnel(SocketImplementation channel, SocketTransport securityLayer, URI proxy) {
        super(channel, securityLayer, proxy);
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return implementation.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()))
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
                    yield CompletableFuture.failedFuture(new SocketException("HTTP : Cannot connect to value, status code " + response.statusCode()));
                }

                implementation.setRemoteAddress(address);
                yield CompletableFuture.completedFuture((Void) null);
            }

            case HttpResult.Redirect<String> _ ->
                    CompletableFuture.failedFuture(new SocketException("HTTP : Invalid redirect while connecting to value"));
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
            builder.append("value-authorization: Basic ")
                    .append(Base64.getEncoder().encodeToString(authInfo.getBytes()))
                    .append("\r\n");
        }
        builder.append("\r\n");
        return securityLayer.write(ByteBuffer.wrap(builder.toString().getBytes()));
    }
}
