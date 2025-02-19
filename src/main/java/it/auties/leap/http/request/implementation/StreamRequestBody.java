package it.auties.leap.http.request.implementation;

import it.auties.leap.http.request.HttpRequestBody;

import java.nio.ByteBuffer;
import java.util.OptionalInt;
import java.util.concurrent.Flow;

public final class StreamRequestBody implements HttpRequestBody {
    private StreamRequestBody() {

    }

    @Override
    public OptionalInt length() {
        return OptionalInt.empty();
    }

    @Override
    public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {

    }
}
