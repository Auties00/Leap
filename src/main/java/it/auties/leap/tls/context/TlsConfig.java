package it.auties.leap.tls.context;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.certificate.TlsCertificatesProvider;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.util.CertificateUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.security.KeyStore;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class TlsConfig {
    private final SocketProtocol protocol;
    private final List<TlsVersion> versions;
    private final List<TlsCipher> ciphers;
    private final List<TlsExtension> extensions;
    private final List<TlsCompression> compressions;
    private final TlsCertificatesProvider certificatesProvider;
    private final TlsCertificatesHandler certificatesHandler;
    private final KeyStore trustedKeyStore;
    private final TlsMessageDeserializer messageDeserializer;

    TlsConfig(
            SocketProtocol protocol,
            List<TlsVersion> versions,
            List<TlsCipher> ciphers,
            List<TlsExtension> extensions,
            List<TlsCompression> compressions,
            TlsCertificatesProvider certificatesProvider,
            TlsCertificatesHandler certificatesHandler,
            KeyStore trustedKeyStore,
            TlsMessageDeserializer messageDeserializer
    ) {
        this.protocol = protocol;
        this.versions = versions;
        this.ciphers = ciphers;
        this.extensions = extensions;
        this.compressions = compressions;
        this.certificatesProvider = certificatesProvider;
        this.certificatesHandler = certificatesHandler;
        this.trustedKeyStore = trustedKeyStore;
        this.messageDeserializer = messageDeserializer;
    }

    public SocketProtocol protocol() {
        return protocol;
    }

    public List<TlsVersion> versions() {
        return versions;
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

    public TlsMessageDeserializer messageDeserializer() {
        return messageDeserializer;
    }

    public TlsConfig withVersions(List<TlsVersion> versions) {
        var checkedVersions = getCheckProtocol(versions);
        return new TlsConfig(
                checkedVersions.getFirst().protocol(),
                checkedVersions,
                this.ciphers,
                this.extensions,
                this.compressions,
                this.certificatesProvider,
                this.certificatesHandler,
                this.trustedKeyStore,
                this.messageDeserializer
        );
    }

    private List<TlsVersion> getCheckProtocol(List<TlsVersion> versions) {
        if(versions == null || versions.isEmpty()) {
            return TlsVersion.recommended(protocol);
        }

        var commonProtocol = versions.getFirst().protocol();
        for (var i = 1; i < versions.size(); i++) {
            if (versions.get(i).protocol() != commonProtocol) {
                throw new TlsException("Protocol mismatch");
            }
        }
        return versions;
    }

    public TlsConfig withCiphers(List<TlsCipher> ciphers) {
        return new TlsConfig(
                protocol,
                this.versions,
                Objects.requireNonNullElse(ciphers, TlsCipher.recommended()),
                this.extensions,
                this.compressions,
                this.certificatesProvider,
                this.certificatesHandler,
                this.trustedKeyStore,
                this.messageDeserializer
        );
    }

    public TlsConfig withExtensions(List<TlsExtension> extensions) {
        return new TlsConfig(
                protocol,
                this.versions,
                this.ciphers,
                Objects.requireNonNullElse(extensions, TlsExtension.required(versions)),
                this.compressions,
                this.certificatesProvider,
                this.certificatesHandler,
                this.trustedKeyStore,
                this.messageDeserializer
        );
    }

    public TlsConfig withCompressions(List<TlsCompression> compressions) {
        return new TlsConfig(
                protocol,
                this.versions,
                this.ciphers,
                this.extensions,
                Objects.requireNonNullElse(compressions, TlsCompression.recommended()),
                this.certificatesProvider,
                this.certificatesHandler,
                this.trustedKeyStore,
                this.messageDeserializer
        );
    }

    public TlsConfig withCertificatesProvider(TlsCertificatesProvider certificatesProvider) {
        return new TlsConfig(
                protocol,
                this.versions,
                this.ciphers,
                this.extensions,
                this.compressions,
                certificatesProvider,
                this.certificatesHandler,
                this.trustedKeyStore,
                this.messageDeserializer
        );
    }

    public TlsConfig withCertificatesHandler(TlsCertificatesHandler certificatesHandler) {
        return new TlsConfig(
                protocol,
                this.versions,
                this.ciphers,
                this.extensions,
                this.compressions,
                this.certificatesProvider,
                Objects.requireNonNullElse(certificatesHandler, TlsCertificatesHandler.validate()),
                this.trustedKeyStore,
                this.messageDeserializer
        );
    }

    public TlsConfig withTrustedKeyStore(KeyStore trustedKeyStore) {
        return new TlsConfig(
                protocol,
                this.versions,
                this.ciphers,
                this.extensions,
                this.compressions,
                this.certificatesProvider,
                this.certificatesHandler,
                Objects.requireNonNullElse(trustedKeyStore, CertificateUtils.defaultKeyStore()),
                this.messageDeserializer
        );
    }

    public TlsConfig withMessageDeserializer(TlsMessageDeserializer messageDeserializer) {
        return new TlsConfig(
                protocol,
                this.versions,
                this.ciphers,
                this.extensions,
                this.compressions,
                this.certificatesProvider,
                this.certificatesHandler,
                this.trustedKeyStore,
                Objects.requireNonNullElse(messageDeserializer, TlsMessageDeserializer.standard())
        );
    }

    public static TlsConfigBuilder newBuilder(SocketProtocol protocol) {
        return new TlsConfigBuilder(protocol);
    }
}
