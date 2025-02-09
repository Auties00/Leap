package it.auties.leap.http;

import it.auties.leap.http.implementation.HttpBytesResponseHandler;
import it.auties.leap.http.implementation.HttpBufferResponseHandler;
import it.auties.leap.http.implementation.HttpTextResponseHandler;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public interface HttpResponseHandler<T> {
    static HttpResponseHandler<String> ofString(Charset charset) {
        return new HttpTextResponseHandler(charset);
    }

    static HttpResponseHandler<String> ofString() {
        return new HttpTextResponseHandler(StandardCharsets.UTF_8);
    }

    static HttpResponseHandler<ByteBuffer> ofBuffer() {
        return new HttpBufferResponseHandler();
    }

    static HttpResponseHandler<byte[]> ofBytes() {
        return new HttpBytesResponseHandler();
    }

    HttpResponse<T> decode(int statusCode, byte[] response);
}
