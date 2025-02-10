package it.auties.leap.http.blocking;

import it.auties.leap.http.HttpResponse;
import it.auties.leap.http.HttpResponseDecoder;
import it.auties.leap.http.HttpResponseHandler;
import it.auties.leap.socket.blocking.BlockingSocketApplicationLayer;

public final class BlockingHttpResponseDecoder implements HttpResponseDecoder {
    private final BlockingSocketApplicationLayer applicationLayer;

    public BlockingHttpResponseDecoder(BlockingSocketApplicationLayer applicationLayer) {
        this.applicationLayer = applicationLayer;
    }

    public <T> HttpResponse<T> readResponse(HttpResponseHandler<T> handler) {
        throw new NullPointerException();
    }
}
