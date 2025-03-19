package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class SrpPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final SrpPreMasterSecretGenerator INSTANCE = new SrpPreMasterSecretGenerator();
    private SrpPreMasterSecretGenerator() {

    }

    public static SrpPreMasterSecretGenerator instance() {
        return INSTANCE;
    }


    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
