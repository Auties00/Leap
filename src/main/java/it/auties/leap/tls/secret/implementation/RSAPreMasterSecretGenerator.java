package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class RSAPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final RSAPreMasterSecretGenerator INSTANCE = new RSAPreMasterSecretGenerator();
    private RSAPreMasterSecretGenerator() {

    }

    public static RSAPreMasterSecretGenerator instance() {
        return INSTANCE;
    }
    
    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
