package it.auties.leap.tls.key.generator;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

public final class KRB5PreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final KRB5PreMasterSecretGenerator INSTANCE = new KRB5PreMasterSecretGenerator();
    private KRB5PreMasterSecretGenerator() {

    }

    public static KRB5PreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
