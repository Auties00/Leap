package it.auties.leap.http.exchange;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.headers.HttpHeaders;
import it.auties.leap.http.exchange.request.HttpRequest;
import it.auties.leap.http.exchange.response.HttpResponse;

import java.nio.ByteBuffer;

public sealed interface HttpExchange<T> permits HttpRequest, HttpResponse {
    HttpHeaders headers();
    HttpBody<T> body();
    void serialize(HttpVersion version, ByteBuffer buffer);
    int length(HttpVersion version);
}
