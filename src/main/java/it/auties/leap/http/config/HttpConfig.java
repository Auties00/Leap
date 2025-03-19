package it.auties.leap.http.config;

import it.auties.leap.http.HttpVersion;
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

    public HttpConfig withTlsConfig(TlsConfig tlsConfig) {
        return new HttpConfig(
                tlsConfig,
                this.cookieHandler,
                this.keepAlive,
                this.proxy,
                this.version,
                this.redirectPolicy
        );
    }

    public HttpConfig withCookieHandler(CookieHandler cookieHandler) {
        return new HttpConfig(
                this.tlsConfig,
                cookieHandler,
                this.keepAlive,
                this.proxy,
                this.version,
                this.redirectPolicy
        );
    }

    public HttpConfig withKeepAlive(Duration keepAlive) {
        return new HttpConfig(
                this.tlsConfig,
                this.cookieHandler,
                keepAlive,
                this.proxy,
                this.version,
                this.redirectPolicy
        );
    }

    public HttpConfig withProxy(URI proxy) {
        return new HttpConfig(
                this.tlsConfig,
                this.cookieHandler,
                this.keepAlive,
                proxy,
                this.version,
                this.redirectPolicy
        );
    }

    public HttpConfig withVersion(HttpVersion version) {
        return new HttpConfig(
                this.tlsConfig,
                this.cookieHandler,
                this.keepAlive,
                this.proxy,
                version,
                this.redirectPolicy
        );
    }

    public HttpConfig withRedirectPolicy(HttpRedirectHandler redirectPolicy) {
        return new HttpConfig(
                this.tlsConfig,
                this.cookieHandler,
                this.keepAlive,
                this.proxy,
                this.version,
                redirectPolicy
        );
    }
}
