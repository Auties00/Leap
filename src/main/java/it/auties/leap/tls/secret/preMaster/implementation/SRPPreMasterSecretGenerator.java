package it.auties.leap.tls.secret.preMaster.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.preMaster.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

public final class SRPPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final SRPPreMasterSecretGenerator INSTANCE = new SRPPreMasterSecretGenerator();
    private SRPPreMasterSecretGenerator() {

    }

    public static SRPPreMasterSecretGenerator instance() {
        return INSTANCE;
    }


    @Override
    public TlsSecret generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
