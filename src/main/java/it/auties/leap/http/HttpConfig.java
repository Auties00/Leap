package it.auties.leap.http;

import it.auties.leap.http.redirect.HttpRedirectHandler;
import it.auties.leap.tls.context.TlsConfig;

import java.net.CookieHandler;
import java.net.URI;
import java.time.Duration;
import java.util.Optional;

public final class HttpConfig {
    public static final HttpConfig DEFAULTS = HttpConfig.newBuilder()
            .build();

    private final TlsConfig tlsConfig;
    private final CookieHandler cookieHandler;
    private final Duration keepAlive;
    private final URI proxy;
    private final HttpVersion version;
    private final HttpRedirectHandler redirectPolicy;
    HttpConfig(TlsConfig tlsConfig, CookieHandler cookieHandler, Duration keepAlive, URI proxy, HttpVersion version, HttpRedirectHandler redirectPolicy) {
        this.tlsConfig = tlsConfig;
        this.cookieHandler = cookieHandler;
        this.keepAlive = keepAlive;
        this.proxy = proxy;
        this.version = version;
        this.redirectPolicy = redirectPolicy;
    }

    public static HttpConfigBuilder newBuilder() {
        return new HttpConfigBuilder();
    }

    public static HttpConfig defaults() {
        return DEFAULTS;
    }

    public TlsConfig tlsConfig() {
        return tlsConfig;
    }

    public Duration keepAlive() {
        return keepAlive;
    }

    public Optional<URI> proxy() {
        return Optional.ofNullable(proxy);
    }

    public Optional<CookieHandler> cookieHandler() {
        return Optional.ofNullable(cookieHandler);
    }

    public HttpVersion version() {
        return version;
    }

    public HttpRedirectHandler redirectPolicy() {
        return redirectPolicy;
    }
}
