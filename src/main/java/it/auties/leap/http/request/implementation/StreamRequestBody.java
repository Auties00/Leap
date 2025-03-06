package it.auties.leap.http.request.implementation;

import it.auties.leap.http.request.HttpRequestBody;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.OptionalInt;

public final class StreamRequestBody implements HttpRequestBody {
    private final InputStream inputStream;
    private final int chunkSize;
    public StreamRequestBody(InputStream inputStream, int chunkSize) {
        this.inputStream = inputStream;
        this.chunkSize = chunkSize;
    }

    @Override
    public OptionalInt length() {
        return OptionalInt.empty();
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        try {
            var chunk = new byte[chunkSize];
            int read;
            while ((read = inputStream.read(chunk)) != -1) {
                buffer.put(chunk, 0, read);
            }
        }catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }
}
