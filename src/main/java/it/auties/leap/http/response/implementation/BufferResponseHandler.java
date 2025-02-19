package it.auties.leap.http.response.implementation;

import it.auties.leap.http.response.HttpResponse;
import it.auties.leap.http.response.HttpResponseHandler;

import java.nio.ByteBuffer;

public final class BufferResponseHandler implements HttpResponseHandler<ByteBuffer> {
    @Override
    public HttpResponse<ByteBuffer> decode(int statusCode, byte[] response) {
        return new HttpResponse.Result<>(statusCode, response == null ? null : ByteBuffer.wrap(response));
    }
}
