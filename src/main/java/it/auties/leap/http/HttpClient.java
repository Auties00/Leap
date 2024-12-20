package it.auties.leap.http;

import it.auties.leap.http.decoder.HttpDecoder;
import it.auties.leap.http.decoder.HttpResult;
import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.SocketProtocol;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;

// TODO: Implement HTTP2/3
@SuppressWarnings("unused")
public final class HttpClient implements AutoCloseable {
    private static final String HTTP_SCHEME = "http";
    private static final String HTTPS_SCHEME = "https";
    private static final String HTTP_DELIMITER = "\r\n";

    private final HttpConfig configuration;
    private final Map<String, SocketClient> keepAlive;
    private final Executor keepAliveEnforcer;
    public HttpClient() {
        this(HttpConfig.defaults());
    }

    public HttpClient(HttpConfig configuration) {
        Objects.requireNonNull(configuration, "Invalid configuration");
        this.configuration = configuration;
        this.keepAlive = new ConcurrentHashMap<>();
        this.keepAliveEnforcer = CompletableFuture.delayedExecutor(
                configuration.keepAlive().getSeconds(),
                TimeUnit.SECONDS,
                Thread::startVirtualThread
        );
    }

    public <T> CompletableFuture<HttpResponse<T>> send(HttpRequest request, HttpResponse.Converter<T> converter) {
        return createRequestPayload(request)
                .thenComposeAsync(payload -> send(request, converter, payload))
                .orTimeout(request.timeout().getSeconds(), TimeUnit.SECONDS);
    }

    private <T> CompletableFuture<HttpResponse<T>> send(HttpRequest request, HttpResponse.Converter<T> converter, ByteBuffer payload) {
        return getSocketClient(request.uri())
                .thenComposeAsync(socket -> send(request, converter, payload, socket));
    }

    private <T> CompletableFuture<HttpResponse<T>> send(HttpRequest request, HttpResponse.Converter<T> converter, ByteBuffer payload, SocketClient socket) {
        return socket.write(payload)
                .thenComposeAsync(_ -> {
                    var decoder = new HttpDecoder(socket);
                    return decoder.readResponse(request.uri(), converter);
                })
                .thenComposeAsync(result -> switch (result) {
                    case HttpResult.Response<T> response -> {
                        if(response.closeConnection()) {
                            try {
                                socket.close();
                            } catch (IOException _) {

                            }
                        }else {
                            keepAliveEnforcer.execute(() -> {
                                try {
                                    socket.close();
                                } catch (IOException _) {

                                }
                            });
                        }

                        yield CompletableFuture.completedFuture(response.data());
                    }
                    case HttpResult.Redirect<T> redirect -> {
                        request.setUri(redirect.to());
                        yield send(request, converter);
                    }
                })
                .exceptionallyComposeAsync(error -> {
                    try {
                        socket.close();
                    } catch (IOException _) {

                    }
                    return CompletableFuture.failedFuture(error);
                });
    }

    private CompletableFuture<ByteBuffer> createRequestPayload(HttpRequest request) {
        var builder = new StringBuilder();
        builder.append(request.method())
                .append(" ")
                .append(request.uri().getPath())
                .append(request.uri().getQuery() == null || request.uri().getQuery().isEmpty() ? "" : "?" + request.uri().getQuery())
                .append(" HTTP/1.1")
                .append(HTTP_DELIMITER);
        builder.append("host: ")
                .append(request.uri().getHost())
                .append(request.uri().getPort() == -1 ? "" : ":" + request.uri().getPort())
                .append(HTTP_DELIMITER);
        if(!request.headers().containsKey("user-agent")) {
            builder.append("user-agent: Java/%s".formatted(Runtime.version().feature()))
                    .append(HTTP_DELIMITER);
        }

        request.headers().forEach((headerKey, headerValue) -> builder.append(headerKey.trim())
                .append(": ")
                .append(headerValue)
                .append(HTTP_DELIMITER));

        var body = request.body()
                .orElse(null);
        if (body == null) {
            builder.append(HTTP_DELIMITER);
            return CompletableFuture.completedFuture(StandardCharsets.ISO_8859_1.encode(builder.toString()));
        }

        return encodePayload(builder, body);
    }

    private static CompletableFuture<ByteBuffer> encodePayload(StringBuilder payload, HttpRequest.Body body) {
        var bodyLength = body.length();
        if (bodyLength.isEmpty()) {
            throw new UnsupportedOperationException();
        }

        payload.append("content-length: ")
                .append(bodyLength.getAsInt())
                .append(HTTP_DELIMITER);
        var header = payload.toString();
        var out = ByteBuffer.allocate(header.length() + bodyLength.getAsInt() + HTTP_DELIMITER.length());
        var encoded = StandardCharsets.ISO_8859_1.newEncoder()
                .encode(CharBuffer.wrap(header), out, true);
        if(encoded.isError()) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("Cannot encode body, transformer error: " + encoded));
        }

        var future = new CompletableFuture<ByteBuffer>();
        body.subscribe(new BodyHandler(out, future));
        return future;
    }

    private InetSocketAddress toSocketAddress(URI uri) {
        var hostname = Objects.requireNonNull(uri.getHost(), "Missing hostname");
        var port = uri.getPort() != -1 ? uri.getPort() : switch (uri.getScheme().toLowerCase()) {
            case HTTPS_SCHEME -> 443;
            case HTTP_SCHEME -> 80;
            default -> throw new IllegalArgumentException("Unexpected scheme: %s".formatted(uri.getScheme()));
        };
        if (configuration.proxy().isEmpty()) {
            return new InetSocketAddress(hostname, port);
        }

        return InetSocketAddress.createUnresolved(hostname, port);
    }


    private CompletableFuture<SocketClient> getSocketClient(URI uri) {
        try {
            var id = uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort();
            var keptAlive = keepAlive.get(id);
            if(keptAlive != null && keptAlive.isConnected()) {
                return CompletableFuture.completedFuture(keptAlive);
            }

            var proxy = configuration.proxy()
                    .orElse(null);
            var freshSocket = switch (uri.getScheme().toLowerCase()) {
                case HTTP_SCHEME -> {
                    var result = SocketClient.ofPlain(SocketProtocol.TCP, proxy);
                    result.setOption(SocketOption.keepAlive(), true);
                    keepAlive.put(id, result);
                    yield result;
                }
                case HTTPS_SCHEME -> {
                    var result = SocketClient.ofSecure(SocketProtocol.TCP, configuration.tlsConfig(), proxy);
                    result.setOption(SocketOption.keepAlive(), true);
                    keepAlive.put(id, result);
                    yield result;
                }
                default -> throw new IllegalArgumentException("Unexpected scheme: " + uri.getScheme().toLowerCase());
            };
            return freshSocket.connect(toSocketAddress(uri))
                    .thenApply(ignored -> freshSocket);
        }catch (IOException exception) {
            return CompletableFuture.failedFuture(exception);
        }
    }

    @Override
    public void close() {
        keepAlive.forEach((_, value) -> {
            try {
                value.close();
            }catch (IOException _) {

            }
        });
        keepAlive.clear();
    }

    private record BodyHandler(ByteBuffer out, CompletableFuture<ByteBuffer> future) implements Flow.Subscriber<ByteBuffer> {
        private static final byte[] HTTP_END = HTTP_DELIMITER.getBytes(StandardCharsets.ISO_8859_1);

        @Override
        public void onSubscribe(Flow.Subscription subscription) {

        }

        @Override
        public void onNext(ByteBuffer item) {
            if (future.isDone()) {
                return;
            }

            if (out.remaining() < item.remaining()) {
                future.completeExceptionally(new IllegalArgumentException("Cannot encode body, transformer error: reported wrong length"));
                return;
            }

            out.put(item);
        }

        @Override
        public void onError(Throwable throwable) {
            future.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            out.put(HTTP_END);
            future.complete(out);
        }
    }
}
