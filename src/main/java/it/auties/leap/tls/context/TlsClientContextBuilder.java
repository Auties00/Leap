package it.auties.leap.tls.context;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificateStore;
import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionInitializer;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionOwner;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.secret.TlsMasterSecretGenerator;
import it.auties.leap.tls.util.TlsKeyUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.util.List;
import java.util.Objects;

public final class TlsClientContextBuilder extends TlsContextBuilder<TlsClientContextBuilder> {
    private List<? extends TlsExtensionOwner.Client> extensions;

    TlsClientContextBuilder(TlsCertificateStore store) {
        super(store, TlsConnectionType.SERVER);
    }

    public TlsClientContextBuilder extensions(List<? extends TlsExtensionOwner.Client> extensions) {
        this.extensions = extensions;
        return this;
    }

    public TlsContext build() {
        var randomData = Objects.requireNonNullElseGet(this.randomData, TlsKeyUtils::randomData);
        var sessionId = Objects.requireNonNullElseGet(this.sessionId, TlsKeyUtils::randomData);
        var versions = this.versions != null && !this.versions.isEmpty() ? this.versions : TlsVersion.recommended(SocketProtocol.TCP);
        var protocol = versions.getFirst().protocol();
        var dtlsCookie = protocol == SocketProtocol.UDP ? Objects.requireNonNullElseGet(this.dtlsCookie, TlsKeyUtils::randomData) : null;
        var credentials = TlsConnection.of(TlsConnectionType.CLIENT, randomData, sessionId, dtlsCookie);
        var ciphers = Objects.requireNonNullElse(this.ciphers, TlsCipherSuite.recommended());
        var compressions = Objects.requireNonNullElse(this.compressions, TlsCompression.recommended());
        var messageDeserializer = Objects.requireNonNullElse(this.messageDeserializer, TlsMessageDeserializer.builtin());
        var masterSecretGenerator = Objects.requireNonNullElse(this.masterSecretGenerator, TlsMasterSecretGenerator.builtin());
        var connectionInitializer = Objects.requireNonNullElse(this.connectionInitializer, TlsConnectionInitializer.builtin());
        var extensions = Objects.requireNonNullElseGet(this.extensions, () -> {
            if(!versions.contains(TlsVersion.TLS13) && !versions.contains(TlsVersion.DTLS13)) {
                return List.<TlsExtensionOwner.Client>of();
            }

            return List.of(TlsExtension.supportedVersions(), TlsExtension.keyShare(), TlsExtension.signatureAlgorithms());
        });
        return TlsContext.ofClient(versions, extensions, ciphers, compressions, credentials, certificateStore, messageDeserializer, masterSecretGenerator, connectionInitializer);
    }
}
