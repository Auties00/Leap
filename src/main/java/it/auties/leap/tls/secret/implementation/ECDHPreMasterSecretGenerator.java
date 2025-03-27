package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.implementation.ECDHKeyExchange;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

public final class ECDHPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final ECDHPreMasterSecretGenerator INSTANCE = new ECDHPreMasterSecretGenerator();
    private ECDHPreMasterSecretGenerator() {

    }

    public static ECDHPreMasterSecretGenerator instance() {
        return INSTANCE;
    }
    
    @Override
    public TlsSecret generatePreMasterSecret(TlsContext context) {
        var serverKeyExchange = context.remoteConnectionState()
                .orElseThrow(TlsAlert::noRemoteConnectionState)
                .keyExchange()
                .orElseThrow(TlsAlert::noRemoteKeyExchange);
        if(!(serverKeyExchange instanceof ECDHKeyExchange ecdhKeyExchange)) {
            throw TlsAlert.remoteKeyExchangeTypeMismatch("ECDH");
        }

        return ecdhKeyExchange.parameters()
                .orElseThrow(TlsAlert::malformedRemoteKeyExchange)
                .toGroup(context)
                .computeSharedSecret(context);
    }
}
