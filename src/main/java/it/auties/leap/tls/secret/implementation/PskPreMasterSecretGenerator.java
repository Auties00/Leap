package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class PskPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final PskPreMasterSecretGenerator INSTANCE = new PskPreMasterSecretGenerator();
    private PskPreMasterSecretGenerator() {

    }

    public static PskPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
