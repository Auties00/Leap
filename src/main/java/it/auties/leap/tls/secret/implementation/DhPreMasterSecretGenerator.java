package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import java.util.NoSuchElementException;

public final class DhPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final DhPreMasterSecretGenerator INSTANCE = new DhPreMasterSecretGenerator();
    private DhPreMasterSecretGenerator() {

    }

    public static DhPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        return context.localPreferredFiniteField()
                .orElseThrow(() -> new NoSuchElementException("No supported group is a finite field"))
                .computeSharedSecret(context);
    }
}
