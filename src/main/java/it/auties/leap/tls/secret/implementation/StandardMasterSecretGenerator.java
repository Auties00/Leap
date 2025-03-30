package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.secret.TlsMasterSecretGenerator;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsPRF;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsSecret;

import static it.auties.leap.tls.util.TlsKeyUtils.*;

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
                .orElseThrow(TlsAlert::noLocalKeyExchange);
        var preMasterSecret = localKeyExchange
                .preMasterSecret()
                .orElseGet(() -> localKeyExchange.preMasterSecretGenerator().generatePreMasterSecret(context));
        var mode = context.selectedMode();
        var version = context.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var extendedMasterSecretSessionHash = context.getNegotiatedValue(TlsProperty.extendedMasterSecret())
                .map(extendedMasterSecretFlag -> extendedMasterSecretFlag ? new byte[0] : null)
                .orElse(null);
        var clientRandom = switch (mode) {
            case CLIENT -> context.localConnectionState()
                    .randomData();
            case SERVER -> context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState)
                    .randomData();
        };
        var serverRandom = switch (mode) {
            case CLIENT -> context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState)
                    .randomData();
            case SERVER -> context.localConnectionState()
                    .randomData();
        };
        var masterSecret = switch (version) {
            case SSL30 -> {
                var result = new byte[LENGTH];
                var md5 = TlsHash.md5();
                var sha = TlsHash.sha1();
                var tmp = new byte[20];
                for (var i = 0; i < 3; i++) {
                    sha.update(SSL3_CONSTANT[i]);
                    sha.update(preMasterSecret.data());
                    sha.update(clientRandom);
                    sha.update(serverRandom);
                    sha.digest(tmp, 0, 20, true);
                    md5.update(preMasterSecret.data());
                    md5.update(tmp);
                    md5.digest(result, i << 4, 16, true);
                }
                yield result;
            }
            case TLS10, TLS11, DTLS10 -> {
                var label = extendedMasterSecretSessionHash != null ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecretSessionHash != null ? extendedMasterSecretSessionHash : TlsPRF.seed(clientRandom, serverRandom);
                yield TlsPRF.tls10Prf(
                        preMasterSecret.data(),
                        label,
                        seed,
                        LENGTH
                );
            }
            case TLS12, DTLS12, TLS13, DTLS13 -> {
                var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                        .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()));
                var label = extendedMasterSecretSessionHash != null ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecretSessionHash != null ? extendedMasterSecretSessionHash : TlsPRF.seed(clientRandom, serverRandom);
                yield TlsPRF.tls12Prf(
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
