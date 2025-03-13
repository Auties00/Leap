package it.auties.leap.http.exchange.serialization;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.headers.HttpMutableHeaders;
import it.auties.leap.http.exchange.response.HttpResponse;
import it.auties.leap.http.exchange.response.HttpResponseStatus;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.async.AsyncSocketIO;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

public final class AsyncHttpSerializer<T> {
    private final AsyncSocketIO client;
    private final HttpBodyDeserializer<T> handler;
    private final ByteBuffer reader;

    public AsyncHttpSerializer(AsyncSocketIO client, HttpBodyDeserializer<T> handler) {
        this.client = client;
        this.handler = handler;
        this.reader = ByteBuffer.allocateDirect(client.getOption(SocketOption.readBufferSize()));
    }

    public CompletableFuture<HttpResponse<T>> decode() {
        return client.read(readBuffer(0))
                .thenCompose(_ -> checkHeader());
    }

    private CompletableFuture<HttpResponse<T>> checkHeader() {
        var start = skipJunk();
        if (start == -1) {
            return client.read(readBuffer(0))
                    .thenCompose(_ -> checkHeader());
        }

        reader.position(start);
        if(reader.remaining() < 5) {
            return client.read(readBuffer(0))
                    .thenCompose(_ -> checkHeader());
        }

        if(reader.get() != 'H' || reader.get() != 'T' || reader.get() != 'T' || reader.get() != 'P' || reader.get() != '/') {
            throw new IllegalArgumentException("Expected HTTP header start");
        }

        return parseMajor();
    }

    private CompletableFuture<HttpResponse<T>> parseMajor() {
        if (!reader.hasRemaining()) {
            return client.read(readBuffer(0))
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
            return client.read(readBuffer(0))
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
            return client.read(readBuffer(0))
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
            return client.read(readBuffer(0))
                    .thenCompose(_ -> skipJunkAndParseStatus(major, minor));
        }

        reader.position(start);
        var version = HttpVersion.of(major, minor)
                .orElseThrow(() -> new IllegalArgumentException("Unknown HTTP version: %s.%s".formatted(major, minor)));
        return parseStatus(version);
    }

    private CompletableFuture<HttpResponse<T>> parseStatus(HttpVersion version) {
        if(reader.remaining() < 3) {
            return client.read(readBuffer(0))
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
            } else if(current == '\r') {
                r = true;
            }else if(current == '\n') {
                if(r) {
                    return parseHeaderKey(version, status, HttpMutableHeaders.newMutableHeaders(), reader.position(), "");
                }
            }else {
                throw new IllegalArgumentException("Expected HTTP reason phrase or end of line");
            }
        }
        var lastR = r;
        return client.read(readBuffer(0))
                .thenCompose(_ -> parseReasonPhraseOrEnd(version, status, lastR));
    }

    private CompletableFuture<HttpResponse<T>> parseHeaderKey(HttpVersion version, HttpResponseStatus status, HttpMutableHeaders headers, int keyStart, String partialKey) {
        if(reader.remaining() < 2) {
            return client.read(readBuffer(keyStart))
                    .thenCompose(_ -> parseHeaderKey(version, status, headers, keyStart, partialKey));
        }

        if(reader.get(keyStart) == '\r' && reader.get(keyStart + 1) == '\n') {
            reader.position(keyStart + 2);
            return parseBody(version, status, headers);
        }

        var limit = reader.limit();
        var keyEnd = keyStart;
        while (keyEnd < limit) {
            var current = reader.get(keyEnd);
            if(current == ':') {
                reader.position(keyEnd + 1);
                var key = partialKey + StandardCharsets.US_ASCII.decode(reader.slice(keyStart, keyEnd - keyStart));
                return parseHeaderValue(version, status, headers, key, reader.position(), "");
            }

            keyEnd++;
        }

        if (keyEnd != reader.capacity()) {
            return client.read(readBuffer(keyEnd))
                    .thenCompose(_ -> parseHeaderKey(version, status, headers, keyStart, partialKey));
        }

        var nextPartialKey = StandardCharsets.US_ASCII.decode(reader.slice(keyStart, keyEnd - keyStart));
        return client.read(readBuffer(0))
                .thenCompose(_ -> parseHeaderKey(version, status, headers, 0, partialKey + nextPartialKey));
    }

    private ByteBuffer readBuffer(int position) {
        return reader.position(position)
                .limit(reader.capacity());
    }

    private CompletableFuture<HttpResponse<T>> parseHeaderValue(HttpVersion version, HttpResponseStatus status, HttpMutableHeaders headers, String headerKey, int valueStart, HeaderValueType headerType, String partialValue) {
        var r = false;
        var limit = reader.limit();
        var valueEnd = valueStart;
        while (valueEnd < limit) {
            var current = reader.get(valueEnd);
            if(current == '\r') {
                r = true;
            }else if(current == '\n') {
                if(r) {
                    reader.position(valueEnd + 1);
                    var value = partialValue + StandardCharsets.US_ASCII.decode(reader.slice(valueStart + 1, valueEnd - valueStart - 2));
                    headers.put(headerKey, value);
                    return parseHeaderKey(version, status, headers, reader.position(), "");
                }
            }else {
                switch (headerType) {
                    case INT -> {
                        if(current == '.') {
                            headerType = HeaderType.FLOAT;
                        } else if(!Character.isDigit(current)) {
                            headerType = HeaderType.STRING;
                        }
                    }
                    case FLOAT -> {
                        if(!Character.isDigit(current)) {
                            headerType = HeaderType.STRING;
                        }
                    }
                    case UNKNOWN -> {
                        if(Character.isDigit(current)) {
                            headerType = HeaderType.INT;
                        }else {
                            headerType = HeaderType.STRING;
                        }
                    }
                }
            }

            valueEnd++;
        }

        if (valueEnd != reader.capacity()) {
            return client.read(readBuffer(valueEnd))
                    .thenCompose(_ -> parseHeaderValue(version, status, headers, headerKey, valueStart, partialValue));
        }

        var nextPartialValue = StandardCharsets.US_ASCII.decode(reader.slice(valueStart + 1, valueEnd - valueStart));
        return client.read(readBuffer(0))
                .thenCompose(_ -> parseHeaderKey(version, status, headers, 0, partialValue + nextPartialValue));
    }

    private enum HeaderValueType {
        INT,
        FLOAT,
        STRING,
        UNKNOWN
    }

    private CompletableFuture<HttpResponse<T>> parseBody(HttpVersion version, HttpResponseStatus status, HttpMutableHeaders headers) {
        var contentLength = headers.get("Content-Length")

                .orElse(-1);
        throw new UnsupportedOperationException();
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
}
