package it.auties.leap.tls.context;

import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.ciphersuite.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnectionHandler;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.extension.TlsExtensionOwner;

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
        var credentials = buildLocalConnection(TlsConnectionType.SERVER, versions);
        var extensions = buildExtensions(versions);
        var compressions = Objects.requireNonNullElse(this.compressions, TlsCompression.recommended());
        var connectionHandler = Objects.requireNonNullElse(this.connectionHandler, TlsConnectionHandler.instance());
        var certificateValidator = Objects.requireNonNullElseGet(this.certificateValidator, TlsCertificateValidator::validate);
        return TlsContext.ofServer(versions, extensions, ciphers, compressions, credentials, certificateValidator, connectionHandler);
    }
}
