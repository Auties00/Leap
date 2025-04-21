package it.auties.leap.tls.secret.master.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.hash.TlsPrf;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.master.TlsMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

import static it.auties.leap.tls.util.TlsKeyUtils.LABEL_EXTENDED_MASTER_SECRET;
import static it.auties.leap.tls.util.TlsKeyUtils.LABEL_MASTER_SECRET;

public final class StandardMasterSecretGenerator implements TlsMasterSecretGenerator {
    private static final StandardMasterSecretGenerator INSTANCE = new StandardMasterSecretGenerator();
    private static final int LENGTH = 48;
    
    private StandardMasterSecretGenerator() {
        
    }
    
    public static TlsMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public TlsSecret generateMasterSecret(TlsContext context) {
        var localKeyExchange = context.localConnectionState()
                .keyExchange()
                .orElseThrow(() -> new TlsAlert("No local key exchange was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var preMasterSecret = localKeyExchange.preMasterSecret()
                .orElseGet(() -> localKeyExchange.preMasterSecretGenerator().generatePreMasterSecret(context));
        var version = context.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var extendedMasterSecret = context.getNegotiatedValue(TlsProperty.extendedMasterSecret())
                .orElse(false);
        var clientRandom = switch (context.localConnectionState().type()) {
            case CLIENT -> context.localConnectionState()
                    .randomData();
            case SERVER -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .randomData();
        };
        var serverRandom = switch (context.localConnectionState().type()) {
            case CLIENT -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .randomData();
            case SERVER -> context.localConnectionState()
                    .randomData();
        };
        var masterSecret = switch (version) {
            case TLS10, TLS11, DTLS10 -> {
                var label = extendedMasterSecret ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecret ? context.connectionIntegrity().digest() : TlsPrf.seed(clientRandom, serverRandom);
                yield TlsPrf.tls10Prf(
                        preMasterSecret.data(),
                        label,
                        seed,
                        LENGTH
                );
            }
            case TLS12, DTLS12, TLS13, DTLS13 -> {
                var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                        .orElseThrow(() -> new TlsAlert("No cipher was negotiated", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                var label = extendedMasterSecret ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecret ? context.connectionIntegrity().digest() : TlsPrf.seed(clientRandom, serverRandom);
                yield TlsPrf.tls12Prf(
                        preMasterSecret.data(),
                        label,
                        seed,
                        LENGTH,
                        negotiatedCipher.hashFactory().newHash()
                );
            }
        };
        preMasterSecret.destroy();
        return TlsSecret.of(masterSecret);
    }
}
