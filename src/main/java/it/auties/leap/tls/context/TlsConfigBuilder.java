package it.auties.leap.tls.context;

import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.certificate.TlsCertificatesProvider;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.util.CertificateUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.security.KeyStore;
import java.util.List;
import java.util.Objects;

public final class TlsConfigBuilder {
    private TlsVersion version;
    private List<TlsCipher> ciphers;
    private List<TlsExtension> extensions;
    private List<TlsCompression> compressions;
    private TlsCertificatesProvider certificatesProvider;
    private TlsCertificatesHandler certificatesHandler;
    private KeyStore trustedKeyStore;
    private TlsMessageDeserializer messageDeserializer;

    TlsConfigBuilder() {

    }

    public TlsConfigBuilder version(TlsVersion version) {
        this.version = version;
        return this;
    }

    public TlsConfigBuilder ciphers(List<TlsCipher> ciphers) {
        this.ciphers = ciphers;
        return this;
    }

    public TlsConfigBuilder extensions(List<TlsExtension> extensions) {
        this.extensions = extensions;
        return this;
    }

    public TlsConfigBuilder compressions(List<TlsCompression> compressions) {
        this.compressions = compressions;
        return this;
    }

    public TlsConfigBuilder certificatesProvider(TlsCertificatesProvider certificatesProvider) {
        this.certificatesProvider = certificatesProvider;
        return this;
    }

    public TlsConfigBuilder certificatesHandler(TlsCertificatesHandler certificatesHandler) {
        this.certificatesHandler = certificatesHandler;
        return this;
    }

    public TlsConfigBuilder trustedKeyStore(KeyStore trustedKeyStore) {
        this.trustedKeyStore = trustedKeyStore;
        return this;
    }

    public TlsConfigBuilder messageDeserializer(TlsMessageDeserializer messageDeserializer) {
        this.messageDeserializer = messageDeserializer;
        return this;
    }

    public TlsConfig build() {
        return new TlsConfig(
                Objects.requireNonNull(this.version, "Missing tls version"),
                Objects.requireNonNullElseGet(ciphers, TlsCipher::secureCiphers),
                Objects.requireNonNull(extensions, "Missing tls extensions"),
                Objects.requireNonNullElseGet(compressions, () -> List.of(TlsCompression.none())),
                certificatesProvider,
                Objects.requireNonNullElseGet(certificatesHandler, TlsCertificatesHandler::validate),
                Objects.requireNonNullElseGet(trustedKeyStore, CertificateUtils::getDefaultKeyStore),
                Objects.requireNonNullElseGet(messageDeserializer, TlsMessageDeserializer::standard)
        );
    }
}
