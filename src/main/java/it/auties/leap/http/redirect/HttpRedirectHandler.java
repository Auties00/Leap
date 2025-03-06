package it.auties.leap.http.redirect;

import it.auties.leap.http.HttpClient;
import it.auties.leap.http.redirect.implementation.AlwaysRedirectHandler;
import it.auties.leap.http.redirect.implementation.NeverRedirectHandler;
import it.auties.leap.http.redirect.implementation.NormalRedirectHandler;

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
