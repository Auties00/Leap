package it.auties.leap.http.blocking;

import it.auties.leap.http.response.HttpResponse;
import it.auties.leap.http.response.HttpResponseDecoder;
import it.auties.leap.http.response.HttpResponseHandler;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;

public final class BlockingHttpResponseDecoder implements HttpResponseDecoder {
    private final BlockingSocketApplicationLayer applicationLayer;

    public BlockingHttpResponseDecoder(BlockingSocketApplicationLayer applicationLayer) {
        this.applicationLayer = applicationLayer;
    }

    public <T> HttpResponse<T> decode(HttpResponseHandler<T> handler) {
        throw new NullPointerException();
    }
}
