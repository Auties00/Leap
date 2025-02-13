package it.auties.leap.tls.key.generator;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

public final class PSKPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final PSKPreMasterSecretGenerator INSTANCE = new PSKPreMasterSecretGenerator();
    private PSKPreMasterSecretGenerator() {

    }

    public static PSKPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
