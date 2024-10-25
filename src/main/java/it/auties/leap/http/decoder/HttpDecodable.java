package it.auties.leap.http.decoder;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public interface HttpDecodable {
    CompletableFuture<ByteBuffer> read();

    CompletableFuture<ByteBuffer> readFully(int size);
}
