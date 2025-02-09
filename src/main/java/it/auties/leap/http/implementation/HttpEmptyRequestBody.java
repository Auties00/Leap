package it.auties.leap.http.implementation;

import it.auties.leap.http.HttpRequestBody;

import java.nio.ByteBuffer;
import java.util.OptionalInt;
import java.util.concurrent.Flow;

public final class HttpEmptyRequestBody implements HttpRequestBody {
    private static final HttpEmptyRequestBody INSTANCE = new HttpEmptyRequestBody();

    private HttpEmptyRequestBody() {

    }

    public static HttpRequestBody instance() {
        return INSTANCE;
    }

    @Override
    public OptionalInt length() {
        return OptionalInt.empty();
    }

    @Override
    public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {

    }
}
