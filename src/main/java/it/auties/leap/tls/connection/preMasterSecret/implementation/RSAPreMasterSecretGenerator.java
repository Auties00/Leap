package it.auties.leap.tls.connection.preMasterSecret.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.preMasterSecret.TlsPreMasterSecretGenerator;
import it.auties.leap.tls.property.TlsProperty;

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
    public byte[] generatePreMasterSecret(TlsContext context) {
        try {
            var preMasterSecret = getPreMasterSecret(context);
            var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            var remotePublicKey = context.remoteConnectionState()
                    .flatMap(TlsConnection::publicKey)
                    .orElseThrow(TlsAlert::noRemoteConnectionState);
            cipher.init(Cipher.WRAP_MODE, remotePublicKey);
            return cipher.wrap(new SecretKeySpec(preMasterSecret, "raw"));
        }catch (Throwable throwable) {
            throw TlsAlert.preMasterSecretError(throwable); // Should never happen
        }
    }

    private static byte[] getPreMasterSecret(TlsContext context) {
        try {
            var preMasterSecret = new byte[48];
            SecureRandom.getInstanceStrong().nextBytes(preMasterSecret);
            var version = context.getNegotiatedValue(TlsProperty.version())
                    .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()));
            preMasterSecret[0] = version.id().minor();
            preMasterSecret[1] = version.id().major();
            return preMasterSecret;
        }catch (NoSuchAlgorithmException _) {
            throw TlsAlert.noSecureRandom();
        }
    }
}
