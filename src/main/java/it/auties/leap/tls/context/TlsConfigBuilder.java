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
import java.util.List;
import java.util.Objects;

public final class TlsConfigBuilder {
    private final SocketProtocol protocol;
    private List<TlsVersion> versions;
    private List<TlsCipher> ciphers;
    private List<TlsExtension> extensions;
    private List<TlsCompression> compressions;
    private TlsCertificatesProvider certificatesProvider;
    private TlsCertificatesHandler certificatesHandler;
    private KeyStore trustedKeyStore;
    private TlsMessageDeserializer messageDeserializer;
    private TlsContextUpdateHandler contextUpdateHandler;

    TlsConfigBuilder(SocketProtocol protocol) {
        this.protocol = protocol;
    }

    public TlsConfigBuilder versions(List<TlsVersion> versions) {
        if(versions != null && !versions.isEmpty()) {
            for (var version : versions) {
                if (version.protocol() != protocol) {
                    throw new TlsException("Protocol mismatch");
                }
            }
        }
        this.versions = versions;
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

    public TlsConfigBuilder contextUpdateHandler(TlsContextUpdateHandler contextUpdateHandler) {
        this.contextUpdateHandler = contextUpdateHandler;
        return this;
    }

    public TlsConfig build() {
        var versions = this.versions != null && !this.versions.isEmpty() ? this.versions : TlsVersion.recommended(protocol);
        return new TlsConfig(
                protocol,
                versions,
                Objects.requireNonNullElse(ciphers, TlsCipher.recommended()),
                Objects.requireNonNullElse(extensions, TlsExtension.required(versions)),
                Objects.requireNonNullElse(compressions, TlsCompression.recommended()),
                certificatesProvider,
                Objects.requireNonNullElse(certificatesHandler, TlsCertificatesHandler.validate()),
                Objects.requireNonNullElse(trustedKeyStore, CertificateUtils.defaultKeyStore()),
                Objects.requireNonNullElse(messageDeserializer, TlsMessageDeserializer.standard()),
                Objects.requireNonNullElse(contextUpdateHandler, TlsContextUpdateHandler.standard())
        );
    }
}
