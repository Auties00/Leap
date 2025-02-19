package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class SRPPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final SRPPreMasterSecretGenerator INSTANCE = new SRPPreMasterSecretGenerator();
    private SRPPreMasterSecretGenerator() {

    }

    public static SRPPreMasterSecretGenerator instance() {
        return INSTANCE;
    }


    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
