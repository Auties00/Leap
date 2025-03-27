package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

public final class DHPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final DHPreMasterSecretGenerator INSTANCE = new DHPreMasterSecretGenerator();
    private DHPreMasterSecretGenerator() {

    }

    public static DHPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public TlsSecret generatePreMasterSecret(TlsContext context) {
        return context.getNegotiatedValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.supportedGroups()))
                .stream()
                .filter(entry -> entry instanceof TlsSupportedFiniteField)
                .findFirst()
                .orElseThrow(TlsAlert::noSupportedFiniteField)
                .computeSharedSecret(context);
    }
}
