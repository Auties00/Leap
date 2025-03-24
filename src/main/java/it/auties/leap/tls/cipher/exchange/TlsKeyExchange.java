package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.util.CertificateUtils;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.Optional;

public interface TlsKeyExchange {
    TlsKeyExchangeType type();
    TlsPreMasterSecretGenerator preMasterSecretGenerator();
    default Optional<byte[]> preMasterSecret() {
        return Optional.empty();
    }
    void serialize(ByteBuffer buffer);
    int length();

    default void acceptsOrThrow(X509Certificate certificate, TlsContext context) {
        var mode = context.selectedMode()
                .orElseThrow(() -> new TlsException("No mode was selected yet"));
        CertificateUtils.validateUsage(certificate, type(), mode);
    }
}
