package it.auties.leap.http.async;

import it.auties.leap.http.HttpClient;
import it.auties.leap.http.config.HttpConfig;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.request.HttpRequest;
import it.auties.leap.http.exchange.response.HttpResponse;
import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.AsyncSocketClient;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class AsyncHttpClient implements HttpClient {
    private final HttpConfig config;
    private final ScheduledExecutorService terminator;

    private AsyncHttpClient(HttpConfig config) {
        this.config = config;
        var keepAlive = config.keepAlive().toSeconds();
        this.terminator = keepAlive > 0 ? Executors.newSingleThreadScheduledExecutor(Thread.ofVirtual().factory()) : null;
    }

    public static AsyncHttpClient newHTTPClient() {
        return new AsyncHttpClient(HttpConfig.defaults());
    }

    public static AsyncHttpClient newHTTPClient(HttpConfig config) {
        return new AsyncHttpClient(config);
    }

    public <T> CompletableFuture<HttpResponse<T>> send(HttpRequest<?> request, HttpBodyDeserializer<T> handler) {
        AsyncSocketClient socket = null;
        try {
            socket = SocketClient.newBuilder()
                    .async(SocketProtocol.TCP)
                    .secure(config.tlsConfig())
                    .build();
            var address = createAddress(request);
            return doSend(request, handler, socket, address);
        }catch (Throwable throwable) {
            if(socket != null && socket.isConnected()) {
                closeSilently(socket);
            }
            return CompletableFuture.failedFuture(throwable);
        }
    }

    private <T> CompletableFuture<HttpResponse<T>> doSend(HttpRequest<?> request, HttpBodyDeserializer<T> handler, AsyncSocketClient socket, InetSocketAddress address) {
        return socket.connect(address)
                .thenCompose(_ -> {
                    var buffer = ByteBuffer.allocateDirect(1024);
                    request.serialize(config.version(), buffer);
                    buffer.flip();
                    return socket.write(buffer)
                            .thenCompose(_ -> HttpResponse.deserializeAsync(socket, handler));
                })
                .thenApply(response -> {
                    var clientKeepAlive = request.headers()
                            .connection()
                            .filter(type -> type.equalsIgnoreCase("Keep-Alive"))
                            .isPresent();
                    var serverKeepAlive = response.headers()
                            .connection()
                            .filter(type -> type.equalsIgnoreCase("Keep-Alive"))
                            .isPresent();
                    if(terminator != null && clientKeepAlive && serverKeepAlive) {
                        terminator.schedule(() -> closeSilently(socket), config.keepAlive().toSeconds(), TimeUnit.SECONDS);
                    }else {
                        closeSilently(socket);
                    }
                    return response;
                })
                .exceptionallyCompose(throwable -> {
                    closeSilently(socket);
                    return CompletableFuture.failedFuture(throwable);
                });
    }

    private InetSocketAddress createAddress(HttpRequest<?> request) {
        var uriPort = request.uri().getPort();
        var uriHost = request.uri().getHost();
        var uriScheme = request.uri().getScheme();
        var fixedPort = uriPort != -1 ? uriPort : switch (uriScheme) {
            case "http" -> 80;
            case "https" -> 443;
            default -> throw new IllegalStateException("Unexpected value: " + uriScheme);
        };
        return config.proxy().isPresent() ? InetSocketAddress.createUnresolved(uriHost, fixedPort)
                : new InetSocketAddress(uriHost, fixedPort);
    }

    private void closeSilently(AsyncSocketClient socket) {
        try {
            socket.close();
        } catch (IOException _) {

        }
    }

    @Override
    public void close() {
        for(var runnable : terminator.shutdownNow()) {
            runnable.run();
        }
    }
}
