package it.auties.leap.integrity;

import it.auties.leap.tls.cipher.mode.GCMMode;
import it.auties.leap.tls.message.TlsMessage;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class EngineIntegrity {
    public static void main(String[] args) throws GeneralSecurityException{
        var key = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        var message = new byte[96];
        ThreadLocalRandom.current().nextBytes(message);
        bcEncrypt(key, message);
        lpEncrypt(key, message);
    }

    private static void bcEncrypt(byte[] key, byte[] message) throws GeneralSecurityException {
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(96, new byte[12]));
        cipher.updateAAD(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
        var output = ByteBuffer.allocate(1024);
        var result = cipher.doFinal(ByteBuffer.wrap(message), output);
        System.out.println(result);
        System.out.println(Arrays.toString(Arrays.copyOfRange(output.array(), 0, result)));

    }

    private static void lpEncrypt(byte[] key, byte[] message) {
        var bcEngine = new it.auties.leap.tls.cipher.engine.AESEngine(key.length);
        bcEngine.init(true, key);
        var input = ByteBuffer.wrap(message);
        var output = ByteBuffer.allocate(1024);
        var mode = new GCMMode(bcEngine);
        mode.init(null, new byte[8]);
        mode.updateAAD(ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}));
        mode.cipher(TlsMessage.ContentType.APPLICATION_DATA.id(), input, output, null);
        System.out.println(Arrays.toString(Arrays.copyOfRange(output.array(), output.position(), output.limit())));
    }
}
