package it.auties.leap.tls.context;

import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.ciphersuite.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnectionHandler;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.extension.TlsExtensionOwner;

import java.util.Objects;

public final class TlsClientContextBuilder extends TlsContextBuilder<TlsClientContextBuilder, TlsExtensionOwner.Client> {
    TlsClientContextBuilder() {
        super(TlsConnectionType.SERVER);
    }

    public TlsContext build() {
        var versions = buildVersions();
        var credentials = buildLocalConnection(TlsConnectionType.CLIENT, versions);
        var ciphers = Objects.requireNonNullElse(this.ciphers, TlsCipherSuite.recommended());
        var compressions = Objects.requireNonNullElse(this.compressions, TlsCompression.recommended());
        var connectionHandler = Objects.requireNonNullElse(this.connectionHandler, TlsConnectionHandler.instance());
        var extensions = buildExtensions(versions);
        var certificateValidator = Objects.requireNonNullElseGet(this.certificateValidator, TlsCertificateValidator::validate);
        return TlsContext.ofClient(versions, extensions, ciphers, compressions, credentials, certificateValidator, connectionHandler);
    }
}
