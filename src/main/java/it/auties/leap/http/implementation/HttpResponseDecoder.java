package it.auties.leap.http.implementation;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.response.HttpResponse;
import it.auties.leap.http.exchange.response.HttpResponseStatus;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.async.AsyncSocketIO;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public final class HttpResponseDecoder<T> implements HttpResponseDecoder {


    public CompletableFuture<HttpResponse<T>> decode(AsyncSocketIO io, HttpResponseDeserializer<T> handler) {
        var reader = ByteBuffer.allocateDirect(client.getOption(SocketOption.readBufferSize()));
        return client.read(reader.position(0))
                .thenCompose(_ -> checkHeader());
    }

    private CompletableFuture<HttpResponse<T>> checkHeader() {
        var start = skipJunk();
        if (start == -1) {
            return client.read(reader.position(0))
                    .thenCompose(_ -> checkHeader());
        }

        reader.position(start);
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
        if (!reader.hasRemaining()) {
            return client.read(reader.position(0))
                    .thenCompose(_ -> parseMajor());
        }

        var digit = reader.get();
        if(!Character.isDigit(digit)) {
            throw new IllegalArgumentException("Expected digit for major HTTP version");
        }

        return parseMinorOrSeparator(digit - '0');
    }

    private CompletableFuture<HttpResponse<T>> parseMinorOrSeparator(int major) {
        if(!reader.hasRemaining()) {
            return client.read(reader.position(0))
                    .thenCompose(_ -> parseMinorOrSeparator(major));
        }
        return switch (reader.get()) {
            case '.' -> parseMinor(major);
            case ' ' -> skipJunkAndParseStatus(major, 0);
            default -> throw new IllegalArgumentException("Expected either header separator(<space>) or version separator(.)");
        };
    }

    private CompletableFuture<HttpResponse<T>> parseMinor(int major) {
        if(!reader.hasRemaining()) {
            return client.read(reader.position(0))
                    .thenCompose(_ -> parseMinor(major));
        }

        var digit = reader.get();
        if(!Character.isDigit(digit)) {
            throw new IllegalArgumentException("Expected digit for minor HTTP version");
        }

        return skipJunkAndParseStatus(major, digit - '0');
    }

    private CompletableFuture<HttpResponse<T>> skipJunkAndParseStatus(int major, int minor) {
        var start = skipJunk();
        if (start == -1) {
            return client.read(reader.position(0))
                    .thenCompose(_ -> skipJunkAndParseStatus(major, minor));
        }

        reader.position(start);
        var version = HttpVersion.of(major, minor)
                .orElseThrow(() -> new IllegalArgumentException("Unknown HTTP version: %s.%s".formatted(major, minor)));
        return parseStatus(version);
    }

    private CompletableFuture<HttpResponse<T>> parseStatus(HttpVersion version) {
        if(reader.remaining() < 3) {
            return client.read(reader.position(0))
                    .thenCompose(_ -> parseStatus(version));
        }

        var digit2 = reader.get();
        var digit1 = reader.get();
        var digit0 = reader.get();
        if(!Character.isDigit(digit2) || !Character.isDigit(digit1) || !Character.isDigit(digit0)) {
            throw new IllegalArgumentException("HTTP status codes should be three digits long");
        }

        var statusCode = ((digit2 - '0') * 100)
                + ((digit1 - '0') * 10)
                + (digit0 - '0');
        var status = HttpResponseStatus.of(statusCode);
        return parseReasonPhraseOrEnd(version, status, false);
    }

    private CompletableFuture<HttpResponse<T>> parseReasonPhraseOrEnd(HttpVersion version, HttpResponseStatus status, boolean r) {
        while (reader.hasRemaining()) {
            var current = reader.get();
            if(Character.isAlphabetic(current) || current == ' ') {
                r = false;
            } if(current == '\r') {
                r = true;
            }else if(current == '\n') {
                if(r) {
                    return parseHeaders(version, status);
                }
            }else {
                throw new IllegalArgumentException("Expected HTTP reason phrase or end of line");
            }
        }
        var lastR = r;
        return client.read(reader.position(0))
                .thenCompose(_ -> parseReasonPhraseOrEnd(version, status, lastR));
    }

    private CompletableFuture<HttpResponse<T>> parseHeaders(HttpVersion version, HttpResponseStatus status) {
        return null;
    }

    private int skipJunk() {
        var position = reader.position();
        var limit = reader.limit();
        while (position < limit) {
            var current = reader.get(position);
            if (current != ' ' && current != '\r' && current != '\n') {
                return position;
            }

            position++;
        }
        return -1;
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
