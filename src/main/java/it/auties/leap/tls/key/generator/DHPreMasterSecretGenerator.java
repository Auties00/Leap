package it.auties.leap.tls.key.generator;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.util.NoSuchElementException;

public final class DHPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final DHPreMasterSecretGenerator INSTANCE = new DHPreMasterSecretGenerator();
    private DHPreMasterSecretGenerator() {

    }

    public static DHPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        return context.localPreferredFiniteField()
                .orElseThrow(() -> new NoSuchElementException("No supported group is a finite field"))
                .computeSharedSecret(context);
    }
}
