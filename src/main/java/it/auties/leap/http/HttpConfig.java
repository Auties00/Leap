package it.auties.leap.http;

import it.auties.leap.tls.TlsConfig;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

public final class HttpConfig {
    public static final HttpConfig DEFAULTS = HttpConfig.newBuilder()
            .build();

    private final TlsConfig tlsConfig;
    private final Duration keepAlive;
    private final URI proxy;
    HttpConfig(TlsConfig tlsConfig, Duration keepAlive, URI proxy) {
        this.tlsConfig = tlsConfig;
        this.keepAlive = keepAlive;
        this.proxy = proxy;
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

    public static HttpConfigBuilder newBuilder() {
        return new HttpConfigBuilder();
    }

    public static HttpConfig defaults() {
        return DEFAULTS;
    }
}
