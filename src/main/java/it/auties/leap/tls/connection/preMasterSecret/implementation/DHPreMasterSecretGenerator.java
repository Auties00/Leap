package it.auties.leap.tls.connection.preMasterSecret.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.connection.preMasterSecret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.property.TlsProperty;

public final class DHPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final DHPreMasterSecretGenerator INSTANCE = new DHPreMasterSecretGenerator();
    private DHPreMasterSecretGenerator() {

    }

    public static DHPreMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        return context.getNegotiatedValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.supportedGroups()))
                .stream()
                .filter(entry -> entry instanceof TlsSupportedFiniteField)
                .findFirst()
                .orElseThrow(TlsAlert::noSupportedFiniteField)
                .computeSharedSecret(context);
    }
}
