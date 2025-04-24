package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.hash.TlsHkdf;
import it.auties.leap.tls.hash.TlsHmac;
import it.auties.leap.tls.hash.TlsPrf;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;

import java.util.Arrays;

import static it.auties.leap.tls.util.TlsKeyUtils.LABEL_EXTENDED_MASTER_SECRET;
import static it.auties.leap.tls.util.TlsKeyUtils.LABEL_MASTER_SECRET;

public final class MasterSecretGenerator implements TlsMasterSecretGenerator {
    private static final MasterSecretGenerator INSTANCE = new MasterSecretGenerator();
    private static final int LENGTH = 48;

    private MasterSecretGenerator() {

    }

    public static TlsMasterSecretGenerator instance() {
        return INSTANCE;
    }

    @Override
    public TlsSecret generateMasterSecret(TlsContext context) {
        var version = context.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var preMasterSecret = getPreMasterSecret(context);
        System.out.println("Pre master secret: " + Arrays.toString(preMasterSecret.data()));
        var masterSecret = switch (version) {
            case TLS10, TLS11, DTLS10 -> {
                var extendedMasterSecret = context.getNegotiatedValue(TlsProperty.extendedMasterSecret())
                        .orElse(false);
                var clientRandom = getClientRandom(context);
                var serverRandom = getServerRandom(context);
                var label = extendedMasterSecret ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecret ? context.connectionHandshakeHash().digest() : TlsPrf.seed(clientRandom, serverRandom);
                yield TlsPrf.tls10Prf(
                        preMasterSecret.data(),
                        label,
                        seed,
                        LENGTH
                );
            }
            case TLS12, DTLS12 -> {
                var extendedMasterSecret = context.getNegotiatedValue(TlsProperty.extendedMasterSecret())
                        .orElse(false);
                var clientRandom = getClientRandom(context);
                var serverRandom = getServerRandom(context);
                var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                        .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                var label = extendedMasterSecret ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecret ? context.connectionHandshakeHash().digest() : TlsPrf.seed(clientRandom, serverRandom);
                yield TlsPrf.tls12Prf(
                        preMasterSecret.data(),
                        label,
                        seed,
                        LENGTH,
                        negotiatedCipher.hashFactory().newHash()
                );
            }

            case TLS13, DTLS13 -> {
                var cipher = context.getNegotiatedValue(TlsProperty.cipher())
                        .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                var hashFactory = cipher.hashFactory();
                var hkdf = TlsHkdf.of(TlsHmac.of(hashFactory));
                // TODO: Handle PreSharedKey case: sun.security.ssl.KAKeyDerivation:115
                var zeros = new byte[hashFactory.length()];
                var earlySecret = hkdf.extract(zeros, zeros);
                var saltSecretContext = hashFactory
                        .newHash()
                        .digest(false);
                var saltSecret = TlsSecret.of(hashFactory, "tls13 derived", saltSecretContext, earlySecret, hashFactory.length());
                var tls13Secret = hkdf.extract(saltSecret.data(), preMasterSecret.data());
                saltSecret.destroy();
                yield tls13Secret;
            }
        };
        preMasterSecret.destroy();
        return TlsSecret.of(masterSecret);
    }

    private byte[] getServerRandom(TlsContext context) {
        return switch (context.localConnectionState().type()) {
            case CLIENT -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .randomData();
            case SERVER -> context.localConnectionState()
                    .randomData();
        };
    }

    private byte[] getClientRandom(TlsContext context) {
        return switch (context.localConnectionState().type()) {
            case CLIENT -> context.localConnectionState()
                    .randomData();
            case SERVER -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .randomData();
        };
    }

    private TlsSecret getPreMasterSecret(TlsContext context) {
        var localKeyExchange = context.localConnectionState()
                .keyExchange()
                .orElseThrow(() -> new TlsAlert("No local key exchange was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        return localKeyExchange.preMasterSecret()
                .orElseGet(() -> localKeyExchange.preMasterSecretGenerator().generatePreMasterSecret(context));
    }
}
