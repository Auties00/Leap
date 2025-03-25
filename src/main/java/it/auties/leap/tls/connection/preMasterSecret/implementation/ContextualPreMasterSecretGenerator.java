package it.auties.leap.tls.connection.preMasterSecret.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.connection.preMasterSecret.TlsPreMasterSecretGenerator;

public final class ContextualPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final ContextualPreMasterSecretGenerator INSTANCE = new ContextualPreMasterSecretGenerator();
    private ContextualPreMasterSecretGenerator() {

    }

    public static ContextualPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
