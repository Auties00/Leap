package it.auties.leap.tls.key.generator;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

public final class ECDHPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final ECDHPreMasterSecretGenerator INSTANCE = new ECDHPreMasterSecretGenerator();
    private ECDHPreMasterSecretGenerator() {

    }

    public static ECDHPreMasterSecretGenerator instance() {
        return INSTANCE;
    }
    
    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        return context.supportedGroups()
                .getFirst()
                .computeSharedSecret(context);
    }
}
