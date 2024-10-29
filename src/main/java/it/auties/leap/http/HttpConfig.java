package it.auties.leap.http;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.net.URI;
import java.time.Duration;
import java.util.Objects;

public final class HttpConfig {
    private static final HttpConfig DEFAULT = new HttpConfig();

    SSLContext sslContext;
    SSLParameters sslParameters;
    Duration keepAliveDuration;
    URI proxy;

    public HttpConfig() {
        try {
            this.sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, null, null);
            this.sslParameters = sslContext.getDefaultSSLParameters();
            this.keepAliveDuration = Duration.ofSeconds(10);
            this.proxy = null;
        } catch (Throwable throwable) {
            throw new RuntimeException("Cannot initialize config", throwable);
        }
    }

    public static HttpConfig defaults() {
        return DEFAULT;
    }

    public HttpConfig sslContext(SSLContext sslContext) {
        Objects.requireNonNull(sslContext, "Invalid ssl context");
        this.sslContext = sslContext;
        return this;
    }

    public HttpConfig sslParameters(SSLParameters sslParameters) {
        Objects.requireNonNull(sslParameters, "Invalid ssl parameters");
        this.sslParameters = sslParameters;
        return this;
    }

    public HttpConfig keepAliveDuration(Duration keepAliveDuration) {
        Objects.requireNonNull(keepAliveDuration, "Invalid keep alive duration");
        this.keepAliveDuration = keepAliveDuration;
        return this;
    }

    public HttpConfig proxy(URI proxy) {
        this.proxy = proxy;
        return this;
    }
}
