package it.auties.leap.tls.secret.preMaster.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.preMaster.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

public final class GroupPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final GroupPreMasterSecretGenerator INSTANCE = new GroupPreMasterSecretGenerator();
    private GroupPreMasterSecretGenerator() {

    }

    public static GroupPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public TlsSecret generatePreMasterSecret(TlsContext context) {
        return context.localConnectionState()
                .ephemeralKeyPair()
                .orElseThrow(() -> new TlsAlert("No ephemeral key pair was generated for local connection", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .group()
                .computeSharedSecret(context);
    }
}
