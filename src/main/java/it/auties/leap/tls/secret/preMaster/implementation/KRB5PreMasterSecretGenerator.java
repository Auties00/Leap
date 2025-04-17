package it.auties.leap.tls.secret.preMaster.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.preMaster.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

public final class KRB5PreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final KRB5PreMasterSecretGenerator INSTANCE = new KRB5PreMasterSecretGenerator();
    private KRB5PreMasterSecretGenerator() {

    }

    public static KRB5PreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public TlsSecret generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
