package it.auties.leap.tls.connection.masterSecret;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.connection.masterSecret.implementation.StandardMasterSecretGenerator;

public interface TlsMasterSecretGenerator {
    byte[] generateMasterSecret(TlsContext context);

    static TlsMasterSecretGenerator standard() {
        return StandardMasterSecretGenerator.instance();
    }
}
