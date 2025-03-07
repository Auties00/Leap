package it.auties.leap.http.config.implementation;

import it.auties.leap.http.HttpClient;
import it.auties.leap.http.config.HttpRedirectHandler;

import java.net.URI;

public final class AlwaysRedirectHandler implements HttpRedirectHandler {
    private static final HttpRedirectHandler INSTANCE = new AlwaysRedirectHandler();

    public static HttpRedirectHandler instance() {
        return INSTANCE;
    }

    private AlwaysRedirectHandler() {

    }

    @Override
    public boolean accepts(HttpClient client, URI from, URI to) {
        return true;
    }
}
