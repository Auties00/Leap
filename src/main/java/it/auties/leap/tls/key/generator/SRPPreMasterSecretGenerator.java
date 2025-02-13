package it.auties.leap.tls.key.generator;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

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
