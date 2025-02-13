package it.auties.leap.tls.key.generator;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

// https://www.ietf.org/archive/id/draft-smyshlyaev-tls12-gost-suites-18.html
public final class GOSTR256PreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final GOSTR256PreMasterSecretGenerator INSTANCE = new GOSTR256PreMasterSecretGenerator();
    private GOSTR256PreMasterSecretGenerator() {

    }

    public static GOSTR256PreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
