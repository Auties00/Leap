package it.auties.leap.tls.context;

import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.certificate.TlsCertificatesProvider;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.version.TlsVersion;

import java.security.KeyStore;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public final class TlsConfig {
    private final TlsVersion version;
    private final List<TlsCipher> ciphers;
    private final List<TlsExtension> extensions;
    private final List<TlsCompression> compressions;
    private final TlsCertificatesProvider certificatesProvider;
    private final TlsCertificatesHandler certificatesHandler;
    private final KeyStore trustedKeyStore;

    TlsConfig(
            TlsVersion version,
            List<TlsCipher> ciphers,
            List<TlsExtension> extensions,
            List<TlsCompression> compressions,
            TlsCertificatesProvider certificatesProvider,
            TlsCertificatesHandler certificatesHandler,
            KeyStore trustedKeyStore
    ) {
        this.version = version;
        this.ciphers = ciphers;
        this.extensions = extensions;
        this.compressions = compressions;
        this.certificatesProvider = certificatesProvider;
        this.certificatesHandler = certificatesHandler;
        this.trustedKeyStore = trustedKeyStore;
    }

    public TlsVersion version() {
        return version;
    }

    public List<TlsCipher> ciphers() {
        return Collections.unmodifiableList(ciphers);
    }

    public List<TlsExtension> extensions() {
        return Collections.unmodifiableList(extensions);
    }

    public List<TlsCompression> compressions() {
        return Collections.unmodifiableList(compressions);
    }

    public Optional<TlsCertificatesProvider> certificatesProvider() {
        return Optional.ofNullable(certificatesProvider);
    }

    public TlsCertificatesHandler certificatesHandler() {
        return certificatesHandler;
    }

    public KeyStore trustedKeyStore() {
        return trustedKeyStore;
    }

    public static TlsConfigBuilder newBuilder() {
        return new TlsConfigBuilder();
    }
}
