package it.auties.leap.http.response.implementation;

import it.auties.leap.http.response.HttpResponse;
import it.auties.leap.http.response.HttpResponseHandler;

public final class BytesResponseHandler implements HttpResponseHandler<byte[]> {
    private static final byte[] EMPTY_BYTES = new byte[0];

    @Override
    public HttpResponse<byte[]> decode(int statusCode, byte[] response) {
        return new HttpResponse.Result<>(statusCode, response);
    }
}
