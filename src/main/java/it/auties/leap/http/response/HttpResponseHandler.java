package it.auties.leap.http.response;

import it.auties.leap.http.response.implementation.BytesResponseHandler;
import it.auties.leap.http.response.implementation.BufferResponseHandler;
import it.auties.leap.http.response.implementation.TextResponseHandler;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public interface HttpResponseHandler<T> {
    static HttpResponseHandler<String> ofString(Charset charset) {
        return new TextResponseHandler(charset);
    }

    static HttpResponseHandler<String> ofString() {
        return new TextResponseHandler(StandardCharsets.UTF_8);
    }

    static HttpResponseHandler<ByteBuffer> ofBuffer() {
        return new BufferResponseHandler();
    }

    static HttpResponseHandler<byte[]> ofBytes() {
        return new BytesResponseHandler();
    }

    HttpResponse<T> decode(int statusCode, byte[] response);
}
