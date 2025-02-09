package it.auties.leap.http.implementation;

import it.auties.leap.http.HttpResponse;
import it.auties.leap.http.HttpResponseHandler;

import java.nio.ByteBuffer;

public final class HttpBufferResponseHandler extends HttpResponseHandler<ByteBuffer> {
    @Override
    public HttpResponse<ByteBuffer> decode(int statusCode, byte[] response) {
        return new HttpResponse<>(statusCode, ByteBuffer.wrap(response));
    }
}
