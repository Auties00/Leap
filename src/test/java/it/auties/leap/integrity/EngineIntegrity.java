package it.auties.leap.integrity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class EngineIntegrity {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws GeneralSecurityException{
        var key = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        var message = new byte[96];
        ThreadLocalRandom.current().nextBytes(message);
        bcEncrypt(key, message);
        lpEncrypt(key, message);
    }

    private static void bcEncrypt(byte[] key, byte[] message) throws GeneralSecurityException {
        var cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
        var output = new byte[1024];
        var result = cipher.update(message, 0, message.length, output);
        System.out.println(Arrays.toString(Arrays.copyOfRange(output, 0, result)));
    }

    private static void lpEncrypt(byte[] key, byte[] message) {
        var bcEngine = new it.auties.leap.tls.cipher.engine.AESEngine(key.length);
        bcEngine.init(true, key);
        var input = ByteBuffer.allocate(1024)
                .position(102)
                .put(message)
                .position(102)
                .limit(102 + message.length);
        var cbcV = ByteBuffer.allocate(bcEngine.blockLength());
        var output = ByteBuffer.allocate(1024);
        var blockLength = bcEngine.blockLength();
        for (var j = 0; j < blockLength; j++) {
            cbcV.put(j, (byte) (cbcV.get(j) ^ input.get()));
        }
        bcEngine.update(cbcV.position(0), output);
        while (input.hasRemaining()) {
            for (var j = 0; j < blockLength; j++) {
                cbcV.put(j, (byte) (output.get(output.position() - blockLength + j) ^ input.get()));
            }
            bcEngine.update(cbcV.position(0), output);
        }
        System.out.println(Arrays.toString(Arrays.copyOfRange(output.array(), 0, output.position())));
    }
}
