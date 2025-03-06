package it.auties.leap.http.async;

import it.auties.leap.http.response.HttpResponse;
import it.auties.leap.http.response.HttpResponseDecoder;
import it.auties.leap.http.response.HttpResponseHandler;
import it.auties.leap.socket.async.AsyncSocketIO;

import java.util.concurrent.CompletableFuture;

public final class AsyncHttpResponseDecoder implements HttpResponseDecoder {
    private final AsyncSocketIO client;

    public AsyncHttpResponseDecoder(AsyncSocketIO client) {
        this.client = client;
    }

    public <T> CompletableFuture<HttpResponse<T>> decode(HttpResponseHandler<T> handler) {
        return CompletableFuture.completedFuture(null);
    }
}
