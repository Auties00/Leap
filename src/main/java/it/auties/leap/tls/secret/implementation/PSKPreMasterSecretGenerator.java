package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

public final class PSKPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final PSKPreMasterSecretGenerator INSTANCE = new PSKPreMasterSecretGenerator();
    private PSKPreMasterSecretGenerator() {

    }

    public static PSKPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public TlsSecret generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
