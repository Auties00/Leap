package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class NonePreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final NonePreMasterSecretGenerator INSTANCE = new NonePreMasterSecretGenerator();
    private NonePreMasterSecretGenerator() {

    }

    public static NonePreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
