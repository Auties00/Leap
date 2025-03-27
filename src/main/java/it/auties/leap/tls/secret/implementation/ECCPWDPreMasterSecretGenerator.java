package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

public final class ECCPWDPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final ECCPWDPreMasterSecretGenerator INSTANCE = new ECCPWDPreMasterSecretGenerator();
    private ECCPWDPreMasterSecretGenerator() {

    }

    public static ECCPWDPreMasterSecretGenerator instance() {
        return INSTANCE;
    }
    
    @Override
    public TlsSecret generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
