package it.auties.leap.http.config;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.extension.TlsExtension;
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
                TlsCipher.aes256GcmSha384(),
                TlsCipher.chacha20Poly1305Sha256(),
                TlsCipher.aes128GcmSha256(),
                TlsCipher.ecdheEcdsaWithAes256GcmSha384(),
                TlsCipher.ecdheRsaWithAes256GcmSha384(),
                TlsCipher.dheRsaWithAes256GcmSha384(),
                TlsCipher.ecdheEcdsaWithChacha20Poly1305Sha256(),
                TlsCipher.ecdheRsaWithChacha20Poly1305Sha256(),
                TlsCipher.dheRsaWithChacha20Poly1305Sha256(),
                TlsCipher.ecdheEcdsaWithAes128GcmSha256(),
                TlsCipher.ecdheRsaWithAes128GcmSha256(),
                TlsCipher.dheRsaWithAes128GcmSha256(),
                TlsCipher.ecdheEcdsaWithAes256CbcSha384(),
                TlsCipher.ecdheRsaWithAes256CbcSha384(),
                TlsCipher.dheRsaWithAes256CbcSha256(),
                TlsCipher.ecdheEcdsaWithAes128CbcSha256(),
                TlsCipher.ecdheRsaWithAes128CbcSha256(),
                TlsCipher.dheRsaWithAes128CbcSha256(),
                TlsCipher.ecdheEcdsaWithAes256CbcSha(),
                TlsCipher.ecdheRsaWithAes256CbcSha(),
                TlsCipher.dheRsaWithAes256CbcSha(),
                TlsCipher.ecdheEcdsaWithAes128CbcSha(),
                TlsCipher.ecdheRsaWithAes128CbcSha(),
                TlsCipher.dheRsaWithAes128CbcSha(),
                TlsCipher.rsaWithAes256GcmSha384(),
                TlsCipher.rsaWithAes128GcmSha256(),
                TlsCipher.rsaWithAes256CbcSha256(),
                TlsCipher.rsaWithAes128CbcSha256(),
                TlsCipher.rsaWithAes256CbcSha(),
                TlsCipher.rsaWithAes128CbcSha()
        );
        var extensions = List.of(
                TlsExtension.serverNameIndication(),
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
        DEFAULT_TLS_CONTEXT = TlsContext.newBuilder(SocketProtocol.TCP)
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
