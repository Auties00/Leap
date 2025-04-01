package it.auties.leap.http.config;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.name.TlsNameType;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;
import it.auties.leap.tls.version.TlsVersion;

import java.net.CookieHandler;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

public final class HttpConfigBuilder {
    private static final Duration DEFAULT_KEEP_ALIVE = Duration.ofSeconds(10);
    private static final Duration NO_KEEP_ALIVE = Duration.ofSeconds(-1);
    private static final TlsContext DEFAULT_TLS_CONTEXT;

    static {
        var ciphers = List.of(
                TlsCipherSuite.aes256GcmSha384(),
                TlsCipherSuite.chacha20Poly1305Sha256(),
                TlsCipherSuite.aes128GcmSha256(),
                TlsCipherSuite.ecdheEcdsaWithAes256GcmSha384(),
                TlsCipherSuite.ecdheRsaWithAes256GcmSha384(),
                TlsCipherSuite.dheRsaWithAes256GcmSha384(),
                TlsCipherSuite.ecdheEcdsaWithChacha20Poly1305Sha256(),
                TlsCipherSuite.ecdheRsaWithChacha20Poly1305Sha256(),
                TlsCipherSuite.dheRsaWithChacha20Poly1305Sha256(),
                TlsCipherSuite.ecdheEcdsaWithAes128GcmSha256(),
                TlsCipherSuite.ecdheRsaWithAes128GcmSha256(),
                TlsCipherSuite.dheRsaWithAes128GcmSha256(),
                TlsCipherSuite.ecdheEcdsaWithAes256CbcSha384(),
                TlsCipherSuite.ecdheRsaWithAes256CbcSha384(),
                TlsCipherSuite.dheRsaWithAes256CbcSha256(),
                TlsCipherSuite.ecdheEcdsaWithAes128CbcSha256(),
                TlsCipherSuite.ecdheRsaWithAes128CbcSha256(),
                TlsCipherSuite.dheRsaWithAes128CbcSha256(),
                TlsCipherSuite.ecdheEcdsaWithAes256CbcSha(),
                TlsCipherSuite.ecdheRsaWithAes256CbcSha(),
                TlsCipherSuite.dheRsaWithAes256CbcSha(),
                TlsCipherSuite.ecdheEcdsaWithAes128CbcSha(),
                TlsCipherSuite.ecdheRsaWithAes128CbcSha(),
                TlsCipherSuite.dheRsaWithAes128CbcSha(),
                TlsCipherSuite.rsaWithAes256GcmSha384(),
                TlsCipherSuite.rsaWithAes128GcmSha256(),
                TlsCipherSuite.rsaWithAes256CbcSha256(),
                TlsCipherSuite.rsaWithAes128CbcSha256(),
                TlsCipherSuite.rsaWithAes256CbcSha(),
                TlsCipherSuite.rsaWithAes128CbcSha()
        );
        var extensions = List.of(
                TlsExtension.serverNameIndication(TlsNameType.HOST_NAME),
                TlsExtension.ecPointFormats(),
                TlsExtension.supportedGroups(),
                TlsExtension.nextProtocolNegotiation(),
                TlsExtension.alpn(List.of("http/1.1")),
                TlsExtension.encryptThenMac(),
                TlsExtension.extendedMasterSecret(),
                // TlsExtension.postHandshakeAuth(),
                TlsExtension.signatureAlgorithms(),
                TlsExtension.supportedVersions(),
                TlsExtension.pskExchangeModes(List.of(TlsPSKExchangeMode.pskDheKe())),
                TlsExtension.keyShare(),
                TlsExtension.padding(517)
        );
        var compressions = List.of(
                TlsCompression.none()
        );
        DEFAULT_TLS_CONTEXT = TlsContext.newClientBuilder()
                .versions(List.of(TlsVersion.TLS12))
                .ciphers(ciphers)
                .extensions(extensions)
                .compressions(compressions)
                .build();
    }

    private TlsContext tlsContext;
    private CookieHandler cookieHandler;
    private Duration keepAlive;
    private URI proxy;
    private HttpVersion version;
    private HttpRedirectHandler redirectHandler;

    HttpConfigBuilder() {

    }

    public HttpConfigBuilder tlsContext(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
        return this;
    }

    public HttpConfigBuilder cookieHandler(CookieHandler cookieHandler) {
        this.cookieHandler = cookieHandler;
        return this;
    }

    public HttpConfigBuilder keepAlive(Duration keepAlive) {
        this.keepAlive = keepAlive;
        return this;
    }

    public HttpConfigBuilder noKeepAlive() {
        this.keepAlive = NO_KEEP_ALIVE;
        return this;
    }

    public HttpConfigBuilder proxy(URI proxy) {
        this.proxy = proxy;
        return this;
    }

    public HttpConfigBuilder version(HttpVersion version) {
        this.version = version;
        return this;
    }

    public HttpConfigBuilder redirectHandler(HttpRedirectHandler redirectHandler) {
        this.redirectHandler = redirectHandler;
        return this;
    }

    public HttpConfig build() {
        return new HttpConfig(
                Objects.requireNonNullElse(tlsContext, DEFAULT_TLS_CONTEXT),
                cookieHandler,
                Objects.requireNonNullElse(keepAlive, DEFAULT_KEEP_ALIVE),
                proxy,
                Objects.requireNonNullElse(version, HttpVersion.HTTP_1_1),
                Objects.requireNonNullElse(redirectHandler, HttpRedirectHandler.normal())
        );
    }
}
