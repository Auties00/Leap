package it.auties.leap.http.implementation;

import it.auties.leap.http.HttpRequestBody;

import java.nio.ByteBuffer;
import java.util.OptionalInt;
import java.util.concurrent.Flow;

public final class HttpStreamRequestBody implements HttpRequestBody {
    private HttpStreamRequestBody() {

    }

    @Override
    public OptionalInt length() {
        return OptionalInt.empty();
    }

    @Override
    public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {

    }
}
