package it.auties.leap.tls.ciphersuite.exchange;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.util.CertificateUtils;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsKeyExchange {
    TlsKeyExchangeType type();
    Optional<TlsConnectionSecret> generatePreSharedSecret(TlsContext context);
    void serialize(ByteBuffer buffer);
    int length();

    // FIXME: Do we even need this?
    default void acceptsOrThrow(TlsCertificate certificate, TlsContext context) {
        var mode = context.localConnectionState().type();
        CertificateUtils.validateUsage(certificate, type(), mode);
    }
}
