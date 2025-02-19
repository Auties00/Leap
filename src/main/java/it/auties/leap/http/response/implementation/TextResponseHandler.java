package it.auties.leap.http.response.implementation;

import it.auties.leap.http.response.HttpResponse;
import it.auties.leap.http.response.HttpResponseHandler;

import java.nio.charset.Charset;

public final class TextResponseHandler implements HttpResponseHandler<String> {
    private final Charset charset;

    public TextResponseHandler(Charset charset) {
        this.charset = charset;
    }

    @Override
    public HttpResponse<String> decode(int statusCode, byte[] response) {
        return new HttpResponse.Result<>(statusCode, response == null ? null : new String(response, charset));
    }
}
