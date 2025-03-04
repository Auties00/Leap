package it.auties.leap.tls.secret.implementation;

import it.auties.leap.tls.context.TlsContext;
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
            preMasterSecret[0] = context.config().version().id().minor();
            preMasterSecret[1] = context.config().version().id().major();
            context.setPreMasterSecret(preMasterSecret);
            var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, context.remotePublicKey().orElseThrow());
            return cipher.wrap(new SecretKeySpec(preMasterSecret, "raw"));
        }catch (Throwable throwable) {
            throw new RuntimeException(throwable);
        }
    }
}
