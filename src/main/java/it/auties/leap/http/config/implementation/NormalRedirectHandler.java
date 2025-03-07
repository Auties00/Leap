package it.auties.leap.http.config.implementation;

import it.auties.leap.http.HttpClient;
import it.auties.leap.http.config.HttpRedirectHandler;

import java.net.URI;
import java.util.Objects;

public final class NormalRedirectHandler implements HttpRedirectHandler {
    private static final HttpRedirectHandler INSTANCE = new NormalRedirectHandler();

    public static HttpRedirectHandler instance() {
        return INSTANCE;
    }

    private NormalRedirectHandler() {

    }

    @Override
    public boolean accepts(HttpClient client, URI from, URI to) {
        return Objects.equals(from.getScheme(), "https")
                && Objects.equals(to.getScheme(), "http");
    }
}
