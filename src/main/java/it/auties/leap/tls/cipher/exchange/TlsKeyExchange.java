package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.connection.preMasterSecret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.util.CertificateUtils;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.Optional;

public interface TlsKeyExchange {
    TlsKeyExchangeType type();
    TlsPreMasterSecretGenerator preMasterSecretGenerator();
    void serialize(ByteBuffer buffer);
    int length();

    // Some key exchanges embed the pre master secret (ex. RSA)
    default Optional<byte[]> preMasterSecret() {
        return Optional.empty();
    }

    default void acceptsOrThrow(X509Certificate certificate, TlsContext context) {
        var mode = context.selectedMode()
                .orElseThrow(() -> new TlsAlert("No mode was selected yet"));
        CertificateUtils.validateUsage(certificate, type(), mode);
    }
}
