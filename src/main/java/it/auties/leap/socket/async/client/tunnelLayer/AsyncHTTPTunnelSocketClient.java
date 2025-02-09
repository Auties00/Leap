package it.auties.leap.socket.async.client.tunnelLayer;

import it.auties.leap.http.HttpResponseHandler;
import it.auties.leap.http.HttpStatusCode;
import it.auties.leap.http.client.HttpDecoder;
import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.async.client.AsyncSocketClient;
import it.auties.leap.socket.async.client.AsyncSocketClientTunnel;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public final class AsyncHTTPTunnelSocketClient extends AsyncSocketClientTunnel {
    private final URI proxy;
    public AsyncHTTPTunnelSocketClient(AsyncSocketClient client, URI proxy) {
        super(client);
        this.proxy = proxy;
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return client.implementation()
                .connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()))
                .thenCompose(_ -> sendAuthentication(address))
                .thenCompose(_ -> readAuthenticationResponse(address));
    }

    private CompletableFuture<Void> readAuthenticationResponse(InetSocketAddress address) {
        var decoder = new HttpDecoder(client);
        return decoder.readResponse(null, HttpResponseHandler.ofString())
                .thenCompose(result -> onAuthenticationResponse(result, address))
                .exceptionallyCompose(error -> CompletableFuture.failedFuture(new SocketException("HTTP : Cannot read authentication response", error)));
    }

    private CompletionStage<Void> onAuthenticationResponse(HttpDecoder.HttpResult<String> result, InetSocketAddress address) {
        return switch (result) {
            case HttpDecoder.HttpResult.Response<String> response -> {
                if (response.statusCode() != HttpStatusCode.ok()) {
                    yield CompletableFuture.failedFuture(new SocketException("HTTP : Cannot connect to value, status code " + response.statusCode()));
                }

                client.setAddress(address);
                yield CompletableFuture.completedFuture((Void) null);
            }

            case HttpDecoder.HttpResult.Redirect<String> _ ->
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
        return client.write(ByteBuffer.wrap(builder.toString().getBytes()));
    }
}
