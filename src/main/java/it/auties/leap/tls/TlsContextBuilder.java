package it.auties.leap.tls;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.certificate.TlsCertificatesProvider;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.initializer.TlsConnectionInitializer;
import it.auties.leap.tls.connection.masterSecret.TlsMasterSecretGenerator;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.util.CertificateUtils;
import it.auties.leap.tls.util.TlsKeyUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.security.KeyStore;
import java.util.List;
import java.util.Objects;

public final class TlsContextBuilder {
    private final SocketProtocol protocol;
    private List<TlsVersion> versions;
    private List<TlsCipher> ciphers;
    private List<TlsExtension> extensions;
    private List<TlsCompression> compressions;
    private TlsCertificatesProvider certificatesProvider;
    private TlsCertificatesHandler certificatesHandler;
    private KeyStore trustedKeyStore;
    private TlsMessageDeserializer messageDeserializer;
    private TlsMasterSecretGenerator masterSecretGenerator;
    private TlsConnectionInitializer connectionInitializer;
    private byte[] randomData;
    private byte[] sessionId;
    private byte[] dtlsCookie;

    TlsContextBuilder(SocketProtocol protocol) {
        this.protocol = Objects.requireNonNull(protocol, "Expected a valid protocol");
    }

    public TlsContextBuilder versions(List<TlsVersion> versions) {
        if(versions != null && !versions.isEmpty()) {
            for (var version : versions) {
                if (version.protocol() != protocol) {
                    throw new TlsAlert("Protocol mismatch");
                }
            }
        }
        this.versions = versions;
        return this;
    }

    public TlsContextBuilder ciphers(List<TlsCipher> ciphers) {
        this.ciphers = ciphers;
        return this;
    }

    public TlsContextBuilder extensions(List<TlsExtension> extensions) {
        this.extensions = extensions;
        return this;
    }

    public TlsContextBuilder compressions(List<TlsCompression> compressions) {
        this.compressions = compressions;
        return this;
    }

    public TlsContextBuilder certificatesProvider(TlsCertificatesProvider certificatesProvider) {
        this.certificatesProvider = certificatesProvider;
        return this;
    }

    public TlsContextBuilder certificatesHandler(TlsCertificatesHandler certificatesHandler) {
        this.certificatesHandler = certificatesHandler;
        return this;
    }

    public TlsContextBuilder trustedKeyStore(KeyStore trustedKeyStore) {
        this.trustedKeyStore = trustedKeyStore;
        return this;
    }

    public TlsContextBuilder messageDeserializer(TlsMessageDeserializer messageDeserializer) {
        this.messageDeserializer = messageDeserializer;
        return this;
    }

    public TlsContextBuilder randomData(byte[] randomData) {
        this.randomData = randomData;
        return this;
    }

    public TlsContextBuilder sessionId(byte[] sessionId) {
        this.sessionId = sessionId;
        return this;
    }

    public TlsContextBuilder dtlsCookie(byte[] dtlsCookie) {
        this.dtlsCookie = dtlsCookie;
        return this;
    }

    public TlsContextBuilder masterSecretGenerator(TlsMasterSecretGenerator masterSecretGenerator) {
        this.masterSecretGenerator = masterSecretGenerator;
        return this;
    }

    public TlsContextBuilder connectionInitializer(TlsConnectionInitializer connectionInitializer) {
        this.connectionInitializer = connectionInitializer;
        return this;
    }

    public TlsContext build() {
        var randomData = Objects.requireNonNullElseGet(this.randomData, TlsKeyUtils::randomData);
        var sessionId = Objects.requireNonNullElseGet(this.sessionId, TlsKeyUtils::randomData);
        var dtlsCookie = protocol == SocketProtocol.UDP ? Objects.requireNonNullElseGet(this.dtlsCookie, TlsKeyUtils::randomData) : null;
        var credentials = TlsConnection.of(randomData, sessionId, dtlsCookie);
        var versions = this.versions != null && !this.versions.isEmpty() ? this.versions : TlsVersion.recommended(protocol);
        var extensions = Objects.requireNonNullElseGet(this.extensions, () -> TlsExtension.required(versions));
        var ciphers = Objects.requireNonNullElse(this.ciphers, TlsCipher.recommended());
        var compressions = Objects.requireNonNullElse(this.compressions, TlsCompression.recommended());
        var certificatesHandler = Objects.requireNonNullElse(this.certificatesHandler, TlsCertificatesHandler.validate());
        var trustedKeyStore = Objects.requireNonNullElse(this.trustedKeyStore, CertificateUtils.defaultKeyStore());
        var messageDeserializer = Objects.requireNonNullElse(this.messageDeserializer, TlsMessageDeserializer.standard());
        var masterSecretGenerator = Objects.requireNonNullElse(this.masterSecretGenerator, TlsMasterSecretGenerator.standard());
        var connectionInitializer = Objects.requireNonNullElse(this.connectionInitializer, TlsConnectionInitializer.standard());
        return new TlsContext(versions, extensions, ciphers, compressions, credentials, certificatesProvider, certificatesHandler, trustedKeyStore, messageDeserializer, masterSecretGenerator, connectionInitializer);
    }
}
