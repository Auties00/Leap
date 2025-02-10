package it.auties.leap.http.response;

import it.auties.leap.http.HttpResponse;
import it.auties.leap.http.HttpResponseHandler;

public final class HttpBytesResponseHandler implements HttpResponseHandler<byte[]> {
    private static final byte[] EMPTY_BYTES = new byte[0];

    @Override
    public HttpResponse<byte[]> decode(int statusCode, byte[] response) {
        return new HttpResponse.Result<>(statusCode, response);
    }
}
