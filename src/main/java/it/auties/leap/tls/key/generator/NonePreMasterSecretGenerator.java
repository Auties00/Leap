package it.auties.leap.tls.key.generator;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

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
