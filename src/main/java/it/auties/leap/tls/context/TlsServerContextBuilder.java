package it.auties.leap.tls.context;

import it.auties.leap.tls.certificate.validator.TlsCertificateValidator;
import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnectionInitializer;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.extension.TlsExtensionOwner;
import it.auties.leap.tls.secret.TlsMasterSecretGenerator;

import java.util.Objects;

public final class TlsServerContextBuilder extends TlsContextBuilder<TlsServerContextBuilder, TlsExtensionOwner.Server> {
    TlsServerContextBuilder() {
        super(TlsConnectionType.SERVER);
    }

    public TlsContext build() {
        var versions = buildVersions();
        var ciphers = Objects.requireNonNullElse(this.ciphers, TlsCipherSuite.recommended());
        if(certificates.isEmpty() && ciphers.stream().noneMatch(cipher -> cipher.authFactory().isAnonymous())) {
            throw new IllegalArgumentException("No certificates provided: either provide a certificate or allow the negotiation of an anonymous cipher");
        }
        var credentials = buildLocalConnection(versions);
        var extensions = buildExtensions(versions);
        var compressions = Objects.requireNonNullElse(this.compressions, TlsCompression.recommended());
        var masterSecretGenerator = Objects.requireNonNullElse(this.masterSecretGenerator, TlsMasterSecretGenerator.builtin());
        var connectionInitializer = Objects.requireNonNullElse(this.connectionInitializer, TlsConnectionInitializer.builtin());
        var certificateValidator = Objects.requireNonNullElseGet(this.certificateValidator, TlsCertificateValidator::validate);
        return TlsContext.ofServer(versions, extensions, ciphers, compressions, credentials, certificateValidator, masterSecretGenerator, connectionInitializer);
    }
}
