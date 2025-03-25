package it.auties.leap.tls.connection.masterSecret.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsException;
import it.auties.leap.tls.connection.masterSecret.TlsMasterSecretGenerator;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsPRF;
import it.auties.leap.tls.property.TlsProperty;

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
    public byte[] generateMasterSecret(TlsContext context) {
        var localKeyExchange = context.localConnectionState()
                .keyExchange()
                .orElseThrow(TlsException::noLocalKeyExchange);
        var preMasterKey = localKeyExchange
                .preMasterSecret()
                .orElseGet(() -> localKeyExchange.preMasterSecretGenerator().generatePreMasterSecret(context));
        var mode = context.selectedMode()
                .orElseThrow(TlsException::noModeSelected);
        var version = context.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsException.noNegotiatedProperty(TlsProperty.version()));
        var extendedMasterSecretSessionHash = context.getNegotiatedValue(TlsProperty.extendedMasterSecret())
                .map(extendedMasterSecretFlag -> extendedMasterSecretFlag ? new byte[0] : null)
                .orElse(null);
        var clientRandom = switch (mode) {
            case CLIENT -> context.localConnectionState()
                    .randomData();
            case SERVER -> context.remoteConnectionState()
                    .orElseThrow(TlsException::noRemoteConnectionState)
                    .randomData();
        };
        var serverRandom = switch (mode) {
            case CLIENT -> context.remoteConnectionState()
                    .orElseThrow(TlsException::noRemoteConnectionState)
                    .randomData();
            case SERVER -> context.localConnectionState()
                    .randomData();
        };
        return switch (version) {
            case SSL30 -> {
                var master = new byte[LENGTH];
                var md5 = TlsHash.md5();
                var sha = TlsHash.sha1();
                var tmp = new byte[20];
                for (var i = 0; i < 3; i++) {
                    sha.update(SSL3_CONSTANT[i]);
                    sha.update(preMasterKey);
                    sha.update(clientRandom);
                    sha.update(serverRandom);
                    sha.digest(tmp, 0, 20, true);
                    md5.update(preMasterKey);
                    md5.update(tmp);
                    md5.digest(master, i << 4, 16, true);
                }
                yield master;
            }
            case TLS10, TLS11, DTLS10 -> {
                var label = extendedMasterSecretSessionHash != null ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecretSessionHash != null ? extendedMasterSecretSessionHash : TlsPRF.seed(clientRandom, serverRandom);
                yield TlsPRF.tls10Prf(
                        preMasterKey,
                        label,
                        seed,
                        LENGTH
                );
            }
            case TLS12, DTLS12, TLS13, DTLS13 -> {
                var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                        .orElseThrow(() -> TlsException.noNegotiatedProperty(TlsProperty.cipher()));
                var label = extendedMasterSecretSessionHash != null ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecretSessionHash != null ? extendedMasterSecretSessionHash : TlsPRF.seed(clientRandom, serverRandom);
                yield TlsPRF.tls12Prf(
                        preMasterKey,
                        label,
                        seed,
                        LENGTH,
                        negotiatedCipher.hashFactory().newHash()
                );
            }
        };
    }
}
