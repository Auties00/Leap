package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class EccPwdPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final EccPwdPreMasterSecretGenerator INSTANCE = new EccPwdPreMasterSecretGenerator();
    private EccPwdPreMasterSecretGenerator() {

    }

    public static EccPwdPreMasterSecretGenerator instance() {
        return INSTANCE;
    }
    
    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
