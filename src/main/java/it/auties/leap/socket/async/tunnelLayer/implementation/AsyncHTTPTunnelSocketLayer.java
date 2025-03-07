package it.auties.leap.socket.async.tunnelLayer.implementation;

import it.auties.leap.http.exchange.response.HttpResponse;
import it.auties.leap.http.exchange.response.HttpResponseStatus;
import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayer;
import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayerFactory;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public final class AsyncHTTPTunnelSocketLayer extends AsyncSocketTunnelLayer {
    private static final AsyncSocketTunnelLayerFactory FACTORY = AsyncHTTPTunnelSocketLayer::new;

    private final URI proxy;
    public AsyncHTTPTunnelSocketLayer(AsyncSocketApplicationLayer applicationLayer, URI proxy) {
        super(applicationLayer);
        this.proxy = proxy;
    }

    public static AsyncSocketTunnelLayerFactory factory() {
        return FACTORY;
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return applicationLayer.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()))
                .thenCompose(_ -> sendAuthentication(address))
                .thenCompose(_ -> readAuthenticationResponse(address));
    }

    private CompletableFuture<Void> readAuthenticationResponse(InetSocketAddress address) {
        return HttpResponseDeserializer.ofString()
                .deserialize(applicationLayer)
                .thenCompose(result -> onAuthenticationResponse(result, address))
                .exceptionallyCompose(error -> CompletableFuture.failedFuture(new SocketException("HTTP : Cannot read authentication response", error)));
    }

    private CompletionStage<Void> onAuthenticationResponse(HttpResponse<String> result, InetSocketAddress address) {
        return switch (result) {
            case HttpResponse.Result<String> response -> {
                if (response.status() != HttpResponseStatus.ok()) {
                    yield CompletableFuture.failedFuture(new SocketException("HTTP : Cannot connect to value, status code " + response.status()));
                }

                applicationLayer.setAddress(address);
                yield CompletableFuture.completedFuture((Void) null);
            }

            case HttpResponse.Redirect<String> _ ->
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
        return applicationLayer.write(ByteBuffer.wrap(builder.toString().getBytes()));
    }
}
