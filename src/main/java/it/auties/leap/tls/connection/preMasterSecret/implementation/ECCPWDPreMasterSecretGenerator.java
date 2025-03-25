package it.auties.leap.tls.connection.preMasterSecret.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.connection.preMasterSecret.TlsPreMasterSecretGenerator;

public final class ECCPWDPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final ECCPWDPreMasterSecretGenerator INSTANCE = new ECCPWDPreMasterSecretGenerator();
    private ECCPWDPreMasterSecretGenerator() {

    }

    public static ECCPWDPreMasterSecretGenerator instance() {
        return INSTANCE;
    }
    
    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
