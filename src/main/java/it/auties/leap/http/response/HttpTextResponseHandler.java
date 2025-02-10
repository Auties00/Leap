package it.auties.leap.http.response;

import it.auties.leap.http.HttpResponse;
import it.auties.leap.http.HttpResponseHandler;

import java.nio.charset.Charset;

public final class HttpTextResponseHandler implements HttpResponseHandler<String> {
    private final Charset charset;

    public HttpTextResponseHandler(Charset charset) {
        this.charset = charset;
    }

    @Override
    public HttpResponse<String> decode(int statusCode, byte[] response) {
        return new HttpResponse.Result<>(statusCode, response == null ? null : new String(response, charset));
    }
}
