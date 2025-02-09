package it.auties.leap.http.implementation;

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
        if(response == null) {
            return new HttpResponse<>(statusCode, null);
        }else {
            var body = new String(response, charset);
            return new HttpResponse<>(statusCode, body);
        }
    }
}
