package it.auties.leap.tls.secret;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.implementation.MasterSecretGenerator;

public interface TlsMasterSecretGenerator {
    TlsSecret generateMasterSecret(TlsContext context);

    static TlsMasterSecretGenerator builtin() {
        return MasterSecretGenerator.instance();
    }
}
