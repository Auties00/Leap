package it.auties.leap.http;

import it.auties.leap.tls.*;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class HttpConfig {
    private static final Duration DEFAULT_KEEP_ALIVE = Duration.ofSeconds(10);
    private static final Duration NO_KEEP_ALIVE = Duration.ofSeconds(-1);

    private final TlsConfig tlsConfig;
    private final Duration keepAlive;
    private final URI proxy;
    private HttpConfig(TlsConfig tlsConfig, Duration keepAlive, URI proxy) {
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

    public static Builder builder() {
        return new Builder();
    }

    public static HttpConfig defaults() {
        return HttpConfig.builder().build();
    }

    public static TlsConfig.Builder defaultTlsConfigBuilder() {
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
                TlsExtension.pskExchangeModes(List.of(TlsPskKeyExchangeMode.PSK_DHE_KE)),
                TlsExtension.keyShare(),
                TlsExtension.padding(517)
        );
        var compressions = List.of(
                TlsCompression.none()
        );
        return TlsConfig.builder()
                .version(TlsVersion.TLS12)
                .ciphers(ciphers)
                .extensions(extensions)
                .compressions(compressions);
    }

    public static final class Builder {
        private TlsConfig tlsConfig;
        private Duration keepAliveDuration;
        private URI proxy;
        private Builder() {

        }

        public Builder tlsConfig(TlsConfig tlsConfig) {
            this.tlsConfig = tlsConfig;
            return this;
        }

        public Builder keepAlive(Duration keepAliveDuration) {
            this.keepAliveDuration = keepAliveDuration;
            return this;
        }

        public Builder noKeepAlive() {
            this.keepAliveDuration = NO_KEEP_ALIVE;
            return this;
        }

        public Builder proxy(URI proxy) {
            this.proxy = proxy;
            return this;
        }

        public HttpConfig build() {
            return new HttpConfig(
                    Objects.requireNonNullElseGet(tlsConfig, () -> defaultTlsConfigBuilder().build()),
                    Objects.requireNonNullElse(keepAliveDuration, DEFAULT_KEEP_ALIVE),
                    proxy
            );
        }
    }
}
