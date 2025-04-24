package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsSecret;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class SupportedGroupPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final SupportedGroupPreMasterSecretGenerator INSTANCE = new SupportedGroupPreMasterSecretGenerator();
    private SupportedGroupPreMasterSecretGenerator() {

    }

    public static SupportedGroupPreMasterSecretGenerator instance() {
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
