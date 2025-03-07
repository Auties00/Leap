package it.auties.leap.http.config;

import it.auties.leap.http.HttpClient;
import it.auties.leap.http.config.implementation.AlwaysRedirectHandler;
import it.auties.leap.http.config.implementation.NeverRedirectHandler;
import it.auties.leap.http.config.implementation.NormalRedirectHandler;

import java.net.URI;

public interface HttpRedirectHandler {
    static HttpRedirectHandler never() {
        return NeverRedirectHandler.instance();
    }

    static HttpRedirectHandler always() {
        return AlwaysRedirectHandler.instance();
    }

    static HttpRedirectHandler normal() {
        return NormalRedirectHandler.instance();
    }

    boolean accepts(HttpClient client, URI from, URI to);
}
