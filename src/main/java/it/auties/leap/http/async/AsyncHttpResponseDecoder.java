package it.auties.leap.http.async;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.response.HttpResponse;
import it.auties.leap.http.response.HttpResponseDecoder;
import it.auties.leap.http.response.HttpResponseHandler;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.async.AsyncSocketIO;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public final class AsyncHttpResponseDecoder<T> implements HttpResponseDecoder {
    private final AsyncSocketIO client;
    // TODO: Maybe this can be optimized into AsyncSocketIO
    private final ByteBuffer reader;
    private final HttpResponseHandler<T> handler;

    public AsyncHttpResponseDecoder(AsyncSocketIO client, HttpResponseHandler<T> handler) {
        this.client = client;
        this.reader = ByteBuffer.allocateDirect(client.getOption(SocketOption.readBufferSize()));
        this.handler = handler;
    }

    public CompletableFuture<HttpResponse<T>> decode() {
        return client.read(reader.position(0))
                .thenCompose(_ -> skipJunk());
    }

    private CompletableFuture<HttpResponse<T>> skipJunk() {
        while (reader.hasRemaining()
                && (reader.get(reader.position()) == ' '
                    || reader.get(reader.position()) == '\n'
                    || reader.get(reader.position()) == '\r')) {
            reader.get();
        }
        if(!reader.hasRemaining()) {
            return decode();
        }else {
            return checkHeader();
        }
    }

    private CompletableFuture<HttpResponse<T>> checkHeader() {
        if(reader.remaining() < 5) {
            return client.read(reader.position(0))
                    .thenCompose(_ -> checkHeader());
        }

        if(reader.get() != 'H' || reader.get() != 'T' || reader.get() != 'T' || reader.get() != 'P' || reader.get() != '/') {
            throw new IllegalArgumentException("Expected HTTP header start");
        }

        return parseMajor();
    }

    private CompletableFuture<HttpResponse<T>> parseMajor() {
        var majorChar = next();
        if (majorChar == null) {
            return client.read(reader.position(0))
                    .thenCompose(_ -> parseMajor());
        }

        return parseMinorOrSeparator(majorChar - '0');
    }

    private CompletableFuture<HttpResponse<T>> parseMinorOrSeparator(int major) {
        var minorOrSeparatorChar = next();
        return switch (minorOrSeparatorChar) {
            case '.' -> parseMinor(major);
            case ' ' -> {
                var version = HttpVersion.of(major, 0)
                        .orElseThrow(() -> new IllegalArgumentException("Unknown HTTP version: %s.%s".formatted(major, 0)));
                yield parseStatus(version);
            }
            case null -> client.read(reader.position(0))
                    .thenCompose(_ -> parseMinorOrSeparator(major));
            default -> throw new IllegalArgumentException("Expected either header separator(<space>) or version separator(.)");
        };
    }

    private CompletableFuture<HttpResponse<T>> parseMinor(int major) {
        var minorChar = next();
        if(minorChar == null) {
            return client.read(reader.position(0))
                    .thenCompose(_ -> parseMinor(major));
        }

        var minor = minorChar - '0';
        var version = HttpVersion.of(major, minor)
                .orElseThrow(() -> new IllegalArgumentException("Unknown HTTP version: %s.%s".formatted(major, minor)));
        return parseStatus(version);
    }

    private CompletableFuture<HttpResponse<T>> parseStatus(HttpVersion version) {
        return null;
    }

    private boolean assertNext(char next) {
        if (!hasNext()) {
            return false;
        }

        if (reader.get() == next) {
            return true;
        }

        throw new IllegalArgumentException("Unexpected character: " + next);
    }

    private boolean hasNext() {
        return reader.hasRemaining();
    }

    private Byte next() {
        if(!reader.hasRemaining()) {
            return null;
        }

        return reader.get();
    }
}
