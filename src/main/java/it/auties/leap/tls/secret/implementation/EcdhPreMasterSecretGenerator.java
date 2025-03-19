package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.cipher.exchange.implementation.ECDHKeyExchange;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

public final class EcdhPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final EcdhPreMasterSecretGenerator INSTANCE = new EcdhPreMasterSecretGenerator();
    private EcdhPreMasterSecretGenerator() {

    }

    public static EcdhPreMasterSecretGenerator instance() {
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
