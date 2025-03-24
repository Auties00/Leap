package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.cipher.exchange.implementation.ECDHKeyExchange;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class ECDHPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final ECDHPreMasterSecretGenerator INSTANCE = new ECDHPreMasterSecretGenerator();
    private ECDHPreMasterSecretGenerator() {

    }

    public static ECDHPreMasterSecretGenerator instance() {
        return INSTANCE;
    }
    
    @Override
    public byte[] generatePreMasterSecret(TlsContext context) {
        var remoteKeyExchange = context.remoteKeyExchange()
                .orElseThrow(() -> new TlsException("Missing remote key exchange"));
        if(!(remoteKeyExchange instanceof ECDHKeyExchange serverKeyExchange)) {
            throw new TlsException("Unsupported key");
        }
        return serverKeyExchange.parameters()
                .orElseThrow(() -> new TlsException("Missing remote ECDH key exchange"))
                .toGroup(context)
                .computeSharedSecret(context);
    }
}
