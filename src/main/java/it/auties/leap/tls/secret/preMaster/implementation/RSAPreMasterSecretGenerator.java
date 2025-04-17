package it.auties.leap.tls.secret.preMaster.implementation;

import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.group.TlsKeyPair;
import it.auties.leap.tls.secret.preMaster.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsSecret;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class RSAPreMasterSecretGenerator implements TlsPreMasterSecretGenerator {
    private static final RSAPreMasterSecretGenerator INSTANCE = new RSAPreMasterSecretGenerator();
    private RSAPreMasterSecretGenerator() {

    }

    public static RSAPreMasterSecretGenerator instance() {
        return INSTANCE;
    }
    
    @Override
    public TlsSecret generatePreMasterSecret(TlsContext context) {
        try {
            var preMasterSecret = getPreMasterSecret(context);
            var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            var remotePublicKey = context.remoteConnectionState()
                    .flatMap(TlsConnection::ephemeralKeyPair)
                    .map(TlsKeyPair::publicKey)
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            cipher.init(Cipher.WRAP_MODE, remotePublicKey);
            return TlsSecret.of(cipher.wrap(new SecretKeySpec(preMasterSecret, "raw")));
        }catch (Throwable throwable) {
            throw new TlsAlert("Cannot generate pre master secret: " + throwable.getMessage(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR); // Should never happen
        }
    }

    private static byte[] getPreMasterSecret(TlsContext context) {
        try {
            var preMasterSecret = new byte[48];
            SecureRandom.getInstanceStrong().nextBytes(preMasterSecret);
            var version = context.getNegotiatedValue(TlsProperty.version())
                    .orElseThrow(() -> {
                        throw new TlsAlert("Missing negotiable property: " + TlsProperty.version().id(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    });
            preMasterSecret[0] = version.id().minor();
            preMasterSecret[1] = version.id().major();
            return preMasterSecret;
        }catch (NoSuchAlgorithmException _) {
            throw new TlsAlert("No secure RNG algorithm", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
    }
}
