package it.auties.leap.tls.context;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.certificate.TlsCertificatesConsumer;
import it.auties.leap.tls.certificate.TlsCertificatesSupplier;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnectionInitializer;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.secret.TlsMasterSecretGenerator;
import it.auties.leap.tls.version.TlsVersion;

import java.security.KeyStore;
import java.util.List;

@SuppressWarnings("unchecked")
abstract sealed class TlsContextBuilder<S extends TlsContextBuilder<S>> permits TlsClientContextBuilder, TlsServerContextBuilder {
    final TlsContextMode mode;
    List<TlsVersion> versions;
    List<TlsCipher> ciphers;
    List<TlsCompression> compressions;
    TlsCertificatesSupplier certificatesProvider;
    TlsCertificatesConsumer certificatesHandler;
    KeyStore trustedKeyStore;
    TlsMessageDeserializer messageDeserializer;
    TlsMasterSecretGenerator masterSecretGenerator;
    TlsConnectionInitializer connectionInitializer;
    byte[] randomData;
    byte[] sessionId;
    byte[] dtlsCookie;

    TlsContextBuilder(TlsContextMode mode) {
        this.mode = mode;
    }

    public S versions(List<TlsVersion> versions) {
        if(versions != null && !versions.isEmpty()) {
            var protocol = versions.getFirst().protocol();
            for (var i = 1; i < versions.size(); i++) {
                if (versions.get(i).protocol() != protocol) {
                    throw new TlsAlert("Protocol mismatch");
                }
            }
        }
        this.versions = versions;
        return (S) this;
    }

    public S ciphers(List<TlsCipher> ciphers) {
        this.ciphers = ciphers;
        return (S) this;
    }

    public S compressions(List<TlsCompression> compressions) {
        this.compressions = compressions;
        return (S) this;
    }

    public S certificatesProvider(TlsCertificatesSupplier certificatesProvider) {
        this.certificatesProvider = certificatesProvider;
        return (S) this;
    }

    public S certificatesHandler(TlsCertificatesConsumer certificatesHandler) {
        this.certificatesHandler = certificatesHandler;
        return (S) this;
    }

    public S trustedKeyStore(KeyStore trustedKeyStore) {
        this.trustedKeyStore = trustedKeyStore;
        return (S) this;
    }

    public S messageDeserializer(TlsMessageDeserializer messageDeserializer) {
        this.messageDeserializer = messageDeserializer;
        return (S) this;
    }

    public S randomData(byte[] randomData) {
        this.randomData = randomData;
        return (S) this;
    }

    public S sessionId(byte[] sessionId) {
        this.sessionId = sessionId;
        return (S) this;
    }

    public S dtlsCookie(byte[] dtlsCookie) {
        this.dtlsCookie = dtlsCookie;
        return (S) this;
    }

    public S masterSecretGenerator(TlsMasterSecretGenerator masterSecretGenerator) {
        this.masterSecretGenerator = masterSecretGenerator;
        return (S) this;
    }

    public S connectionInitializer(TlsConnectionInitializer connectionInitializer) {
        this.connectionInitializer = connectionInitializer;
        return (S) this;
    }

    public abstract TlsContext build();
}
