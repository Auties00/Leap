package it.auties.leap.http.async;

import it.auties.leap.http.HttpClient;
import it.auties.leap.http.config.HttpConfig;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.request.HttpRequest;
import it.auties.leap.http.exchange.response.HttpResponse;
import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketProtocol;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public final class AsyncHttpClient implements HttpClient {
    private final HttpConfig config;

    private AsyncHttpClient(HttpConfig config) {
        this.config = config;
    }

    public static AsyncHttpClient newHTTPClient() {
        return new AsyncHttpClient(HttpConfig.defaults());
    }

    public static AsyncHttpClient newHTTPClient(HttpConfig config) {
        return new AsyncHttpClient(config);
    }

    public <T> CompletableFuture<HttpResponse<T>> send(HttpRequest<?> request, HttpBodyDeserializer<T> handler) {
        try (
                var socket = SocketClient.newBuilder()
                        .async(SocketProtocol.TCP)
                        .secure(config.tlsConfig())
                        .build()
        ) {
            socket.connect(new InetSocketAddress(request.uri().getHost(), inferPort(request))).join();
            var buffer = ByteBuffer.allocateDirect(1024);
            request.serialize(config.version(), buffer);
            return socket.write(buffer)
                    .thenCompose(_ -> HttpResponse.deserializeAsync(socket,  handler));
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    private static int inferPort(HttpRequest<?> request) {
        var port = request.uri().getPort();
        if(port != -1) {
            return port;
        }

        return switch (request.uri().getScheme()) {
            case "http" -> 80;
            case "https" -> 443;
            default -> throw new IllegalStateException("Unexpected value: " + request.uri().getScheme());
        };
    }

    @Override
    public void close() throws Exception {

    }
}
