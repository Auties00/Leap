package it.auties.leap.http.config;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.tls.context.TlsContext;

import java.net.CookieHandler;
import java.net.URI;
import java.time.Duration;
import java.util.Optional;

public final class HttpConfig {
    public static final HttpConfig DEFAULTS = HttpConfig.newBuilder()
            .build();

    private final TlsContext tlsContext;
    private final CookieHandler cookieHandler;
    private final Duration keepAlive;
    private final URI proxy;
    private final HttpVersion version;
    private final HttpRedirectHandler redirectPolicy;

    HttpConfig(TlsContext tlsContext, CookieHandler cookieHandler, Duration keepAlive, URI proxy, HttpVersion version, HttpRedirectHandler redirectPolicy) {
        this.tlsContext = tlsContext;
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

    public TlsContext tlsContext() {
        return tlsContext;
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

    public HttpConfig withTlsContext(TlsContext tlsContext) {
        return new HttpConfig(
                tlsContext,
                this.cookieHandler,
                this.keepAlive,
                this.proxy,
                this.version,
                this.redirectPolicy
        );
    }

    public HttpConfig withCookieHandler(CookieHandler cookieHandler) {
        return new HttpConfig(
                this.tlsContext,
                cookieHandler,
                this.keepAlive,
                this.proxy,
                this.version,
                this.redirectPolicy
        );
    }

    public HttpConfig withKeepAlive(Duration keepAlive) {
        return new HttpConfig(
                this.tlsContext,
                this.cookieHandler,
                keepAlive,
                this.proxy,
                this.version,
                this.redirectPolicy
        );
    }

    public HttpConfig withProxy(URI proxy) {
        return new HttpConfig(
                this.tlsContext,
                this.cookieHandler,
                this.keepAlive,
                proxy,
                this.version,
                this.redirectPolicy
        );
    }

    public HttpConfig withVersion(HttpVersion version) {
        return new HttpConfig(
                this.tlsContext,
                this.cookieHandler,
                this.keepAlive,
                this.proxy,
                version,
                this.redirectPolicy
        );
    }

    public HttpConfig withRedirectPolicy(HttpRedirectHandler redirectPolicy) {
        return new HttpConfig(
                this.tlsContext,
                this.cookieHandler,
                this.keepAlive,
                this.proxy,
                this.version,
                redirectPolicy
        );
    }
}
