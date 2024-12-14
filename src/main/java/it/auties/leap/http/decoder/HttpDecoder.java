package it.auties.leap.http.decoder;

import it.auties.leap.http.HttpResponse;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;

// TODO: Rewrite this
public class HttpDecoder {
    private static final byte[] HTTP_MESSAGE_END_BYTES = "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] EMPTY_BUFFER = new byte[0];

    private final HttpDecodable socket;
    private String headers;
    private ByteBuffer body;
    private Integer statusCode;
    private int contentLength;
    private final List<String> contentEncoding;
    private boolean closeConnection;
    private String location;
    private int lastHeaderLineIndex;
    private int currentHeaderLineIndex;
    private boolean partial;
    private final List<HttpEncoding> transferEncoding;
    public HttpDecoder(HttpDecodable socket) {
        this.socket = socket;
        this.headers = null;
        this.body = null;
        this.contentLength = -1;
        this.closeConnection = false;
        this.location = null;
        this.lastHeaderLineIndex = -1;
        this.currentHeaderLineIndex = -1;
        this.partial = true;
        this.transferEncoding = new ArrayList<>();
        this.contentEncoding = new ArrayList<>();
    }
    
    public <T> CompletableFuture<HttpResult<T>> readResponse(URI uri, HttpResponse.Converter<T> converter) {
        return socket.read().thenComposeAsync(responseBuffer -> {
            updateSource(responseBuffer, true);
            return handleResponse(uri, converter);
        });
    }

    private <T> CompletableFuture<HttpResult<T>> handleResponse(URI uri, HttpResponse.Converter<T> converter) {
        var partial = handleStatusCodeAndHeaders();
        if (partial) {
            return readResponse(uri, converter);
        }

        if (isRedirect()) {
            var location = URI.create(Objects.requireNonNull(location(), "Missing location for redirect status code"));
            return CompletableFuture.completedFuture(new HttpResult.Redirect<>(location.isAbsolute() ? location : uri.resolve(location)));
        }

        if(contentLength() == 0) {
            return CompletableFuture.completedFuture(new HttpResult.Response<>(statusCode, closeConnection, converter.empty(statusCode)));
        }

        return (contentLength() == -1 ? readChunkedResponse() : readFullResponse())
                .thenApplyAsync(response -> new HttpResult.Response<>(statusCode, closeConnection, converter.of(statusCode, response)));
    }


    private CompletableFuture<byte[]> readFullResponse() {
        var partialBody = readBody(contentLength());
        if(partialBody != null) {
            return CompletableFuture.completedFuture(partialBody);
        }

        return socket.readFully(contentLength() - remaining())
                .thenApplyAsync(this::concatFullResponse);
    }

    private byte[] concatFullResponse(ByteBuffer additionalBody) {
        var remaining = remaining();
        var result = new byte[remaining + additionalBody.remaining()];
        readBody(result);
        additionalBody.get(result, remaining, additionalBody.remaining());
        return result;
    }

    private boolean handleStatusCodeAndHeaders() {
        while (hasNext()) {
            var responseLine = readHeaderLine();
            setLastHeaderLineIndex(currentHeaderLineIndex());
            if(statusCode == null) {
                if(!responseLine.startsWith("HTTP")) {
                    continue;
                }

                setStatusCode(parseStatusCode(responseLine));
                continue;
            }

            if (responseLine.isEmpty()) {
                finish();
                break;
            }

            var responseLineParts = responseLine.split(":", 2);
            var headerKey = responseLineParts[0];
            var headerValue = responseLineParts.length == 2 ? responseLineParts[1].trim() : "";
            switch (headerKey.toLowerCase()) {
                case "content-length" -> {
                    try {
                        setContentLength(Integer.parseUnsignedInt(headerValue));
                    } catch (NumberFormatException exception) {
                        throw new IllegalArgumentException("Malformed Content-Length header: " + responseLine);
                    }
                }
                case "connection" -> setCloseConnection(headerValue.equalsIgnoreCase("close"));
                case "location" -> setLocation(headerValue);
                case "transfer-encoding" -> transferEncoding().addAll(Arrays.stream(headerValue.split(",")).map(HttpEncoding::of).toList());
                case "content-encoding" -> contentEncoding().addAll(Arrays.stream(headerValue.split(",")).map(String::trim).toList());
            }
        }
        return isPartial();
    }

    private int parseStatusCode(String responseLine) {
        var responseStatusParts = responseLine.split(" ");
        if (responseStatusParts.length < 2) {
            throw new IllegalArgumentException("Unexpected response status code: " + responseLine);
        }

        var statusCode = responseStatusParts[1];
        try {
            return Integer.parseUnsignedInt(statusCode);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Malformed status code: " + responseLine);
        }
    }

    private CompletableFuture<byte[]> readChunkedResponse() {
        var chunkedLength = readChunkedBodyLength();
        if(chunkedLength.truncated()) {
            return socket.read().thenComposeAsync(responseBuffer -> {
                updateSource(responseBuffer, false);
                return readChunkedResponse();
            });
        }

        if(chunkedLength.value() == -1 || !isPartial()) {
            return CompletableFuture.completedFuture(EMPTY_BUFFER);
        }

        return readChunkContent(chunkedLength.value()).thenComposeAsync(currentChunk -> {
            if(!isPartial()) {
                return CompletableFuture.completedFuture(currentChunk);
            }

            return readChunkedResponse()
                    .thenApplyAsync(nextChunk -> concat(currentChunk, nextChunk));
        });
    }

    private static byte[] concat(byte[] first, byte[] second) {
        if (first == null || first.length == 0) {
            return second;
        }

        if (second == null || second.length == 0) {
            return first;
        }

        var result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private CompletableFuture<byte[]> readChunkContent(int chunkedLength) {
        if(remaining() >= chunkedLength + 2) {
            var result = readBody(chunkedLength);
            checkChunkTrailing();
            return CompletableFuture.completedFuture(result);
        }

        return socket.readFully(chunkedLength - remaining() + 2).thenComposeAsync(responseBuffer -> {
            updateSource(responseBuffer, false);
            return readChunkContent(chunkedLength);
        });
    }
    
    private boolean isPartial() {
        return partial;
    }

    private boolean isRedirect() {
        return statusCode == 301
                || statusCode == 302
                || statusCode == 307
                || statusCode == 308;
    }

    private void setStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
    }

    private int contentLength() {
        return contentLength;
    }

    private List<String> contentEncoding() {
        return contentEncoding;
    }

    private String location() {
        return location;
    }

    private List<HttpEncoding> transferEncoding() {
        return transferEncoding;
    }

    private int currentHeaderLineIndex() {
        return currentHeaderLineIndex;
    }

    private void setContentLength(int contentLength) {
        this.contentLength = contentLength;
    }

    private void setCloseConnection(boolean closeConnection) {
        this.closeConnection = closeConnection;
    }

    private void setLastHeaderLineIndex(int lastHeaderLineIndex) {
        this.lastHeaderLineIndex = lastHeaderLineIndex;
    }

    private void setLocation(String location) {
        this.location = location;
    }

    private void finish() {
        this.partial = false;
    }

    private boolean hasNext() {
        return headers != null && (currentHeaderLineIndex = headers.indexOf("\n", lastHeaderLineIndex + 1)) != -1;
    }

    private void updateSource(ByteBuffer response, boolean headers) {
        if(headers) {
            var divider = getMessageContentDivider(response);
            var oldLimit = response.limit();
            if(divider != -1) {
                response.limit(divider);
            }
            var content = StandardCharsets.ISO_8859_1.decode(response).toString();
            if(this.headers == null) {
                this.headers = content;
            }else {
                this.headers = this.headers + content;
            }
            response.limit(oldLimit);
        }

        if(body != null && body.hasRemaining()) {
            var result = new byte[body.remaining() + response.remaining()];
            var i = 0;
            while (body.hasRemaining()) {
                result[i++] = body.get();
            }
            while (response.hasRemaining()) {
                result[i++] = response.get();
            }
            this.body = ByteBuffer.wrap(result);
        }else {
            this.body = response;
        }
    }

    private int getMessageContentDivider(ByteBuffer partialResult) {
        var index = -1;
        for (int i = 0; i < partialResult.remaining() - HTTP_MESSAGE_END_BYTES.length; i++) {
            if(partialResult.get(i) == HTTP_MESSAGE_END_BYTES[0]
                    && partialResult.get(i + 1) == HTTP_MESSAGE_END_BYTES[1]
                    && partialResult.get(i + 2) == HTTP_MESSAGE_END_BYTES[2]
                    && partialResult.get(i + 3) == HTTP_MESSAGE_END_BYTES[3]) {
                index = i + HTTP_MESSAGE_END_BYTES.length;
                break;
            }
        }
        return index;
    }

    private String readHeaderLine() {
        return headers.substring(lastHeaderLineIndex + 1, currentHeaderLineIndex).trim();
    }

    private byte[] readBody(int length) {
        if (body.remaining() < length) {
            return null;
        }

        var result = new byte[length];
        body.get(result);
        return result;
    }

    private void readBody(byte[] destination) {
        if(!body.hasRemaining()) {
            return;
        }

        body.get(destination, 0, body.remaining());
    }

    private ChunkedResult readChunkedBodyLength() {
        var position = body.position();
        var chunkSizeDigitsCount = 0;
        while (position + chunkSizeDigitsCount + 1 >= body.limit()
                || body.get(position + chunkSizeDigitsCount) != '\r'
                || body.get(position + chunkSizeDigitsCount + 1) != '\n') {
            if(position + chunkSizeDigitsCount + 1 >= body.limit()) {
                return new ChunkedResult(-1, transferEncoding.contains(HttpEncoding.CHUNKED));
            }

            chunkSizeDigitsCount++;
        }

        var chunkSize = 0;
        for (var i = 1; i <= chunkSizeDigitsCount; i++) {
            chunkSize += (int) (Character.getNumericValue(body.get()) * Math.pow(16, chunkSizeDigitsCount - i));
        }

        checkChunkTrailing();

        this.partial = chunkSize != 0;
        return new ChunkedResult(chunkSize, false);
    }

    private void checkChunkTrailing() {
        if(body.get() != '\r' || body.get() != '\n') {
            throw new IllegalArgumentException("Truncated chunked message size");
        }
    }

    private int remaining() {
        return body.remaining();
    }

    private record ChunkedResult(int value, boolean truncated) {

    }
}
