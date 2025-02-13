package it.auties.leap.tls.key.generator;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

public final class DHPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final DHPreMasterSecretGenerator INSTANCE = new DHPreMasterSecretGenerator();
    private DHPreMasterSecretGenerator() {

    }

    public static DHPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        return context.supportedGroups()
                .getFirst()
                .computeSharedSecret(context);
    }
}
