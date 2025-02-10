package it.auties.leap.http.request;

import it.auties.leap.http.HttpRequestBody;

import java.nio.ByteBuffer;
import java.util.OptionalInt;
import java.util.concurrent.Flow;

public final class HttpStaticRequestBody implements HttpRequestBody {
    private final ByteBuffer buffer;

    public HttpStaticRequestBody(ByteBuffer buffer) {
        this.buffer = buffer;
    }

    @Override
    public OptionalInt length() {
        return OptionalInt.of(buffer.remaining());
    }

    @Override
    public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {
        subscriber.onNext(buffer);
        subscriber.onComplete();
    }
}
