package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class Krb5PreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final Krb5PreMasterSecretGenerator INSTANCE = new Krb5PreMasterSecretGenerator();
    private Krb5PreMasterSecretGenerator() {

    }

    public static Krb5PreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
