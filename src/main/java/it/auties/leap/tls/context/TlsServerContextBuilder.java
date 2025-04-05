package it.auties.leap.tls.context;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificateStore;
import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionInitializer;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.extension.TlsExtensionOwner;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.secret.TlsMasterSecretGenerator;
import it.auties.leap.tls.util.TlsKeyUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.util.List;
import java.util.Objects;

public final class TlsServerContextBuilder extends TlsContextBuilder<TlsServerContextBuilder> {
    private static final List<? extends TlsExtensionOwner.Server> DEFAULT_EXTENSIONS = List.of();

    private List<? extends TlsExtensionOwner.Server> extensions;

    TlsServerContextBuilder(TlsCertificateStore certificateStore) {
        super(certificateStore, TlsConnectionType.SERVER);
    }

    public TlsServerContextBuilder extensions(List<? extends TlsExtensionOwner.Server> extensions) {
        this.extensions = extensions;
        return this;
    }

    public TlsContext build() {
        var randomData = Objects.requireNonNullElseGet(this.randomData, TlsKeyUtils::randomData);
        var sessionId = Objects.requireNonNullElseGet(this.sessionId, TlsKeyUtils::randomData);
        var versions = this.versions != null && !this.versions.isEmpty() ? this.versions : TlsVersion.recommended(SocketProtocol.TCP);
        var protocol = versions.getFirst().protocol();
        var dtlsCookie = protocol == SocketProtocol.UDP ? Objects.requireNonNullElseGet(this.dtlsCookie, TlsKeyUtils::randomData) : null;
        var credentials = TlsConnection.of(TlsConnectionType.SERVER, randomData, sessionId, dtlsCookie);
        var extensions = Objects.requireNonNullElse(this.extensions, DEFAULT_EXTENSIONS);
        var ciphers = Objects.requireNonNullElse(this.ciphers, TlsCipherSuite.recommended());
        var compressions = Objects.requireNonNullElse(this.compressions, TlsCompression.recommended());
        var messageDeserializer = Objects.requireNonNullElse(this.messageDeserializer, TlsMessageDeserializer.builtin());
        var masterSecretGenerator = Objects.requireNonNullElse(this.masterSecretGenerator, TlsMasterSecretGenerator.builtin());
        var connectionInitializer = Objects.requireNonNullElse(this.connectionInitializer, TlsConnectionInitializer.builtin());
        return TlsContext.ofServer(versions, extensions, ciphers, compressions, credentials, certificateStore, messageDeserializer, masterSecretGenerator, connectionInitializer);
    }
}
