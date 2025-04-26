package it.auties.leap.tls.ciphersuite.exchange;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;
import it.auties.leap.tls.util.CertificateUtils;

import java.nio.ByteBuffer;
import java.util.Optional;

public interface TlsKeyExchange {
    TlsKeyExchangeType type();
    TlsPreMasterSecretGenerator preMasterSecretGenerator();
    void serialize(ByteBuffer buffer);
    int length();

    // Some key exchanges embed the pre master secret (ex. RSA)
    default Optional<TlsSecret> preMasterSecret() {
        return Optional.empty();
    }

    default void acceptsOrThrow(TlsCertificate certificate, TlsContext context) {
        var mode = context.localConnectionState().type();
        CertificateUtils.validateUsage(certificate, type(), mode);
    }
}
