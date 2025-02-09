package it.auties.leap.http.implementation;

import it.auties.leap.http.HttpResponse;
import it.auties.leap.http.HttpResponseHandler;

public final class HttpBytesResponseHandler extends HttpResponseHandler<byte[]> {
    private static final byte[] EMPTY_BYTES = new byte[0];

    @Override
    public HttpResponse<byte[]> decode(int statusCode, byte[] response) {
        return new HttpResponse<>(statusCode, response);
    }

    @Override
    public HttpResponse<byte[]> empty(int statusCode) {
        return new HttpResponse<>(statusCode, EMPTY_BYTES);
    }
}
