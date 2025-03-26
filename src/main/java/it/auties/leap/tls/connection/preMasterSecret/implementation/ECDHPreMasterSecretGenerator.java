package it.auties.leap.tls.connection.preMasterSecret.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.implementation.ECDHKeyExchange;
import it.auties.leap.tls.connection.preMasterSecret.TlsPreMasterSecretGenerator;

public final class ECDHPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final ECDHPreMasterSecretGenerator INSTANCE = new ECDHPreMasterSecretGenerator();
    private ECDHPreMasterSecretGenerator() {

    }

    public static ECDHPreMasterSecretGenerator instance() {
        return INSTANCE;
    }
    
    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
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
