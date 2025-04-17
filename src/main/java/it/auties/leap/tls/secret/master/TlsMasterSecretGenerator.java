package it.auties.leap.tls.secret.master;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsSecret;
import it.auties.leap.tls.secret.master.implementation.StandardMasterSecretGenerator;

public interface TlsMasterSecretGenerator {
    TlsSecret generateMasterSecret(TlsContext context);

    static TlsMasterSecretGenerator builtin() {
        return StandardMasterSecretGenerator.instance();
    }
}
