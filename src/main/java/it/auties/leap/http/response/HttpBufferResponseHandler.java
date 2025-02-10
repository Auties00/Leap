package it.auties.leap.http.response;

import it.auties.leap.http.HttpResponse;
import it.auties.leap.http.HttpResponseHandler;

import java.nio.ByteBuffer;

public final class HttpBufferResponseHandler implements HttpResponseHandler<ByteBuffer> {
    @Override
    public HttpResponse<ByteBuffer> decode(int statusCode, byte[] response) {
        return new HttpResponse.Result<>(statusCode, response == null ? null : ByteBuffer.wrap(response));
    }
}
