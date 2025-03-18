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

import static it.auties.leap.http.exchange.serialization.HttpConstants.*;

public final class AsyncHttpSerializer<T> {
    private AsyncSocketIO client;
    private HttpBodyDeserializer<T> handler;
    private ByteBuffer reader;

    private Integer major;
    private Integer minor;
    private HttpVersion version;
    private HttpResponseStatus status;

    private char crlf = SPACE;
    private HttpMutableHeaders headers;

    private String headerKey = "";
    private String headerValue = "";
    private boolean canSkipSpace = true;

    public CompletableFuture<HttpResponse<T>> decode(AsyncSocketIO client, HttpBodyDeserializer<T> handler) {
        this.client = client;
        this.handler = handler;
        this.reader = ByteBuffer.allocateDirect(client.getOption(SocketOption.readBufferSize()));
        return client.read(readBuffer())
                .thenCompose(_ -> checkHeader());
    }

    private CompletableFuture<HttpResponse<T>> checkHeader() {
        var start = skipJunk();
        if (start == -1) {
            return client.read(readBuffer())
                    .thenCompose(_ -> checkHeader());
        }

        reader.position(start);
        if(reader.remaining() < 5) {
            return client.read(readBuffer())
                    .thenCompose(_ -> checkHeader());
        }

        if(reader.get() != 'H' || reader.get() != 'T' || reader.get() != 'T' || reader.get() != 'P' || reader.get() != '/') {
            throw new IllegalArgumentException("Expected HTTP header start");
        }

        return parseMajor();
    }

    private CompletableFuture<HttpResponse<T>> parseMajor() {
        if (!reader.hasRemaining()) {
            return client.read(readBuffer())
                    .thenCompose(_ -> parseMajor());
        }

        var digit = reader.get();
        if(!Character.isDigit(digit)) {
            throw new IllegalArgumentException("Expected digit for major HTTP version");
        }

        this.major = digit - '0';
        return parseMinorOrSeparator();
    }

    private CompletableFuture<HttpResponse<T>> parseMinorOrSeparator() {
        if(!reader.hasRemaining()) {
            return client.read(readBuffer())
                    .thenCompose(_ -> parseMinorOrSeparator());
        }
        return switch (reader.get()) {
            case '.' -> parseMinor();
            case ' ' -> {
                this.minor = 0;
                yield skipJunkAndParseStatus();
            }
            default -> throw new IllegalArgumentException("Expected either header separator(<space>) or version separator(.)");
        };
    }

    private CompletableFuture<HttpResponse<T>> parseMinor() {
        if(!reader.hasRemaining()) {
            return client.read(readBuffer())
                    .thenCompose(_ -> parseMinor());
        }

        var digit = reader.get();
        if(!Character.isDigit(digit)) {
            throw new IllegalArgumentException("Expected digit for minor HTTP version");
        }

        this.minor = digit - '0';
        return skipJunkAndParseStatus();
    }

    private CompletableFuture<HttpResponse<T>> skipJunkAndParseStatus() {
        var start = skipJunk();
        if (start == -1) {
            return client.read(readBuffer())
                    .thenCompose(_ -> skipJunkAndParseStatus());
        }

        reader.position(start);
        this.version = HttpVersion.of(major, minor)
                .orElseThrow(() -> new IllegalArgumentException("Unknown HTTP version: %s.%s".formatted(major, minor)));
        return parseStatus();
    }

    private CompletableFuture<HttpResponse<T>> parseStatus() {
        if(reader.remaining() < 3) {
            return client.read(readBuffer())
                    .thenCompose(_ -> parseStatus());
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
        this.status = HttpResponseStatus.of(statusCode);
        return parseReasonPhraseOrEnd();
    }

    private CompletableFuture<HttpResponse<T>> parseReasonPhraseOrEnd() {
        while (reader.hasRemaining()) {
            var current = reader.get();
            if(Character.isAlphabetic(current) || current == SPACE) {
                crlf = SPACE;
            } else if(current == CARRIAGE_RETURN) {
                crlf = CARRIAGE_RETURN;
            }else if(current == LINE_FEED) {
                if(crlf == CARRIAGE_RETURN) {
                    crlf = SPACE;
                    this.headers = HttpMutableHeaders.newMutableHeaders();
                    return parseHeaderKey();
                }
            }else {
                throw new IllegalArgumentException("Expected HTTP reason phrase or end of line");
            }
        }
        return client.read(readBuffer())
                .thenCompose(_ -> parseReasonPhraseOrEnd());
    }

    private CompletableFuture<HttpResponse<T>> parseHeaderKey() {
        if(reader.remaining() < 2) {
            return client.read(reader)
                    .thenCompose(_ -> parseHeaderKey());
        }

        var start = reader.position();
        if(reader.get(start) == CARRIAGE_RETURN && reader.get(start + 1) == LINE_FEED) {
            reader.position(start + 2);
            return parseBody(version, status, headers);
        }

        var end = start;
        var limit = reader.limit();
        while (end < limit) {
            var current = reader.get(end);
            if(current == HEADER_SEPARATOR) {
                reader.position(end + 1);
                this.headerKey += StandardCharsets.US_ASCII.decode(reader.slice(start, end - start));
                this.canSkipSpace = true;
                return parseHeaderValue();
            }

            end++;
        }

        this.headerKey += StandardCharsets.US_ASCII.decode(reader.slice(start, end - start));
        return client.read(readBuffer())
                .thenCompose(_ -> parseHeaderKey());
    }

    private CompletableFuture<HttpResponse<T>> parseHeaderValue() {
        var start = reader.position();
        var end = start;
        var limit = reader.limit();
        if(start < limit && canSkipSpace) {
            if(reader.get(start) == SPACE) {
                start++;
            }
            canSkipSpace = false;
        }

        while (end < limit) {
            var current = reader.get(end);
            if(canSkipSpace && current == SPACE) {
                canSkipSpace = false;
            }else if(current == CARRIAGE_RETURN) {
                crlf = CARRIAGE_RETURN;
            }else if(current == LINE_FEED) {
                if(crlf == CARRIAGE_RETURN) {
                    reader.position(end + 1);
                    var value = headerValue + StandardCharsets.US_ASCII.decode(reader.slice(start, end - start - 1));
                    headers.put(headerKey, value);
                    headerKey = "";
                    headerValue = "";
                    canSkipSpace = true;
                    return parseHeaderKey();
                }
            }

            end++;
        }

        headerValue += StandardCharsets.US_ASCII.decode(reader.slice(start, end - start));
        return client.read(readBuffer())
                .thenCompose(_ -> parseHeaderValue());
    }

    private CompletableFuture<HttpResponse<T>> parseBody(HttpVersion version, HttpResponseStatus status, HttpMutableHeaders headers) {
        var contentLength = headers.contentLength()
                .orElse(-1L);
        if(contentLength == -1) {
            throw new UnsupportedOperationException();
        }

        if(reader.remaining() >= contentLength) {
            return CompletableFuture.completedFuture(buildResponse(version, status, headers, reader.slice(reader.position(), Math.toIntExact(contentLength))));
        }

        throw new UnsupportedOperationException();
    }

    private HttpResponse<T> buildResponse(HttpVersion version, HttpResponseStatus status, HttpMutableHeaders headers, ByteBuffer buffer) {
        return HttpResponse.<T>newBuilder()
                .version(version)
                .status(status)
                .headers(headers.toImmutableHeaders())
                .body(handler.deserialize(version, headers, buffer))
                .build();
    }

    private int skipJunk() {
        var position = reader.position();
        var limit = reader.limit();
        while (position < limit) {
            var current = reader.get(position);
            if (current != SPACE && current != CARRIAGE_RETURN && current != LINE_FEED) {
                return position;
            }

            position++;
        }
        return -1;
    }

    private ByteBuffer readBuffer() {
        return reader.position(0)
                .limit(reader.capacity());
    }
}
