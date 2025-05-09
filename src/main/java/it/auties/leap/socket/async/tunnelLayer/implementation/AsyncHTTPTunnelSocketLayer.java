package it.auties.leap.socket.async.tunnelLayer.implementation;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.request.HttpRequest;
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
        return HttpResponse.deserializeAsync(applicationLayer, HttpBodyDeserializer.ofString())
                .thenCompose(result -> onAuthenticationResponse(result, address))
                .exceptionallyCompose(error -> CompletableFuture.failedFuture(new SocketException("HTTP : Cannot read authentication response", error)));
    }

    private CompletionStage<Void> onAuthenticationResponse(HttpResponse<String> result, InetSocketAddress address) {
        if (result.status() != HttpResponseStatus.ok()) {
            return CompletableFuture.failedFuture(new SocketException("HTTP : Cannot connect to value, status code " + result.status()));
        }

        applicationLayer.setAddress(address);
        return CompletableFuture.completedFuture(null);
    }

    private CompletableFuture<Void> sendAuthentication(InetSocketAddress endpoint) {
        var userInfo = proxy.getUserInfo();
        var request = HttpRequest.builder()
                .connect()
                .uri(URI.create(endpoint.getHostName() + ":" + endpoint.getPort()))
                .header("Proxy-Authorization", userInfo == null ? null : "Basic " + Base64.getEncoder().encodeToString(userInfo.getBytes()))
                .build();
        var buffer = ByteBuffer.allocateDirect(request.length(HttpVersion.HTTP_1_1));
        request.serialize(HttpVersion.HTTP_1_1, buffer);
        buffer.flip();
        return applicationLayer.write(buffer);
    }
}
