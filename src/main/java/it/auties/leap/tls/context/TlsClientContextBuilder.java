package it.auties.leap.tls.context;

import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnectionInitializer;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.extension.TlsExtensionOwner;
import it.auties.leap.tls.secret.master.TlsMasterSecretGenerator;

import java.util.Objects;

public final class TlsClientContextBuilder extends TlsContextBuilder<TlsClientContextBuilder, TlsExtensionOwner.Client> {
    TlsClientContextBuilder() {
        super(TlsConnectionType.SERVER);
    }

    public TlsContext build() {
        var versions = buildVersions();
        var credentials = buildLocalConnection(versions);
        var ciphers = Objects.requireNonNullElse(this.ciphers, TlsCipherSuite.recommended());
        var compressions = Objects.requireNonNullElse(this.compressions, TlsCompression.recommended());
        var masterSecretGenerator = Objects.requireNonNullElse(this.masterSecretGenerator, TlsMasterSecretGenerator.builtin());
        var connectionInitializer = Objects.requireNonNullElse(this.connectionInitializer, TlsConnectionInitializer.builtin());
        var extensions = buildExtensions(versions);
        var certificateValidator = Objects.requireNonNullElseGet(this.certificateValidator, TlsCertificateValidator::validate);
        return TlsContext.ofClient(versions, extensions, ciphers, compressions, credentials, certificateValidator, masterSecretGenerator, connectionInitializer);
    }
}
