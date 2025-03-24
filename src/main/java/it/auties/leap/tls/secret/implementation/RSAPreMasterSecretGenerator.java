package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
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
            var preMasterSecret = new byte[48];
            SecureRandom.getInstanceStrong().nextBytes(preMasterSecret);
            var version = context.negotiatedVersion()
                    .orElseThrow(() -> new TlsException("No version was negotiated yet"));
            preMasterSecret[0] = version.id().minor();
            preMasterSecret[1] = version.id().major();
            var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, context.remotePublicKey().orElseThrow());
            return cipher.wrap(new SecretKeySpec(preMasterSecret, "raw"));
        }catch (Throwable throwable) {
            throw new RuntimeException(throwable);
        }
    }
}
