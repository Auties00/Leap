package it.auties.leap.http.implementation;

import it.auties.leap.http.exchange.response.HttpResponse;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;

public final class BlockingHttpResponseDecoder {
    private final BlockingSocketApplicationLayer applicationLayer;

    public BlockingHttpResponseDecoder(BlockingSocketApplicationLayer applicationLayer) {
        this.applicationLayer = applicationLayer;
    }

    public <T> HttpResponse<T> decode(HttpResponseDeserializer<T> handler) {
        throw new NullPointerException();
    }
}
