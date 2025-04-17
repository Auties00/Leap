package it.auties.leap.tls.secret.preMaster.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.preMaster.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

// https://www.ietf.org/archive/id/draft-smyshlyaev-tls12-gost-suites-18.html
public final class GOSTR256PreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final GOSTR256PreMasterSecretGenerator INSTANCE = new GOSTR256PreMasterSecretGenerator();
    private GOSTR256PreMasterSecretGenerator() {

    }

    public static GOSTR256PreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public TlsSecret generatePreMasterSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
