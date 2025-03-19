package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

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
