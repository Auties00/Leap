package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.cipher.exchange.server.implementation.ECDHServerKeyExchange;
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
        var mode = context.selectedMode()
                .orElseThrow(() -> new TlsException("No mode was selected yet"));
        var serverKeyExchange = switch (mode) {
            case CLIENT -> {
                var remoteKeyExchange = context.remoteKeyExchange()
                        .orElseThrow(() -> new TlsException("Missing remote key exchange"));
                if(!(remoteKeyExchange instanceof ECDHServerKeyExchange that)) {
                    throw new TlsException("Unsupported key");
                }
                yield that;
            }
            case SERVER -> {
                var localKeyExchange = context.localKeyExchange()
                        .orElseThrow(() -> new TlsException("Missing local key exchange"));
                if(!(localKeyExchange instanceof ECDHServerKeyExchange that)) {
                    throw new TlsException("Unsupported key");
                }
                yield that;
            }
        };
        return serverKeyExchange.parameters()
                .toGroup(context)
                .computeSharedSecret(context);
    }
}
