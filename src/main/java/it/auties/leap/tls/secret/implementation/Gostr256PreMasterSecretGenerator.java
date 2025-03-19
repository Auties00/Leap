package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

// https://www.ietf.org/archive/id/draft-smyshlyaev-tls12-gost-suites-18.html
public final class Gostr256PreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final Gostr256PreMasterSecretGenerator INSTANCE = new Gostr256PreMasterSecretGenerator();
    private Gostr256PreMasterSecretGenerator() {

    }

    public static Gostr256PreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
