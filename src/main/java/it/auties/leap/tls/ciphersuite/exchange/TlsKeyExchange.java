package it.auties.leap.tls.ciphersuite.exchange;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.property.TlsSerializableProperty;
import it.auties.leap.tls.util.CertificateUtils;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsKeyExchange extends TlsSerializableProperty {
    TlsKeyExchangeType type();
    Optional<TlsConnectionSecret> generatePreSharedSecret(TlsContext context);

    // FIXME: Do we even need this?
    default void acceptsOrThrow(TlsCertificate certificate, TlsContext context) {
        var mode = context.localConnectionState().type();
        CertificateUtils.validateUsage(certificate, type(), mode);
    }
}
