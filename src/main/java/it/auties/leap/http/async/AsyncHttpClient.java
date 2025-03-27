package it.auties.leap.http.async;

import it.auties.leap.http.HttpClient;
import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.config.HttpConfig;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.request.HttpRequest;
import it.auties.leap.http.exchange.response.HttpResponse;
import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.AsyncSocketClient;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public final class AsyncHttpClient implements HttpClient {
    private final HttpConfig config;
    private final Map<InetSocketAddress, Connection> clients;
    private AsyncHttpClient(HttpConfig config) {
        this.config = config;
        this.clients = new ConcurrentHashMap<>();
    }

    public static AsyncHttpClient newHTTPClient() {
        return new AsyncHttpClient(HttpConfig.defaults());
    }

    public static AsyncHttpClient newHTTPClient(HttpConfig config) {
        return new AsyncHttpClient(config);
    }

    public <T> CompletableFuture<HttpResponse<T>> send(HttpRequest<?> request, HttpBodyDeserializer<T> handler) {
        var address = createAddress(request);
        var client = clients.computeIfAbsent(address, (_) -> {
            var underlyingSocket = SocketClient.newBuilder()
                    .async(SocketProtocol.TCP)
                    .secure(config.tlsContext())
                    .build();
            return new Connection(address, underlyingSocket);
        });
        return client.send(config.version(), request, handler);
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

    @Override
    public void close() {
        clients.forEach((_, value) -> value.close());
    }

    private void closeSilently(InetSocketAddress address, AsyncSocketClient socket) {
        try {
            socket.close();
            clients.remove(address);
        } catch (Throwable _) {

        }
    }

    private final class Connection {
        private final InetSocketAddress recipient;
        private final AsyncSocketClient socket;
        private final Set<CompletableFuture<?>> tasks;
        private volatile CompletableFuture<?> connectionFuture;
        private volatile Thread canceller;

        private Connection(InetSocketAddress recipient, AsyncSocketClient socket) {
            this.recipient = recipient;
            this.socket = socket;
            this.tasks = ConcurrentHashMap.newKeySet();
        }

        public <T> CompletableFuture<HttpResponse<T>> send(HttpVersion version, HttpRequest<?> request, HttpBodyDeserializer<T> handler) {
            var task = send0(version, request, handler);
            tasks.add(task);
            return task;
        }

        private <T> CompletableFuture<HttpResponse<T>> send0(HttpVersion version, HttpRequest<?> request, HttpBodyDeserializer<T> handler) {
            if(connectionFuture == null) {
                connectionFuture = socket.connect(recipient);
            }
            return connectionFuture.thenCompose(_ -> {
                        var buffer = ByteBuffer.allocateDirect(1024);
                        request.serialize(version, buffer);
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
                        if(clientKeepAlive && serverKeepAlive) {
                            if(canceller != null && !canceller.isInterrupted()) {
                                canceller.interrupt();
                            }
                            this.canceller = Thread.startVirtualThread(() -> {
                                try {
                                    Thread.sleep(Duration.ofSeconds(10));
                                    closeSilently(recipient, socket);
                                    notifyAll();
                                }catch (InterruptedException _) {

                                }
                            });
                        }else {
                            closeSilently(recipient, socket);
                        }
                        return response;
                    })
                    .exceptionallyCompose(throwable -> {
                        closeSilently(recipient, socket);
                        return CompletableFuture.failedFuture(throwable);
                    });
        }

        public void close() {
            var currentTasks = new HashSet<>(tasks);
            tasks.clear();
            for(var task : currentTasks) {
                task.join();
            }
            if(canceller != null) {
                canceller.interrupt();
                canceller = null;
            }
            closeSilently(recipient, socket);
        }
    }
}
