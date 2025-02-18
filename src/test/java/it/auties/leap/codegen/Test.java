package it.auties.leap.codegen;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class Test {
    public static void main(String[] args) throws Throwable {
        var encrypted = cipher();
        System.out.println(Arrays.toString(decipher(encrypted)));;
    }

    private static byte[] cipher() throws Throwable {
        var gcm = GCMBlockCipher.newInstance(AESEngine.newInstance());
        gcm.init(true, new ParametersWithIV(new KeyParameter(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), new byte[12]));
        var message = new byte[16];
        ThreadLocalRandom.current().nextBytes(message);
        var output = new byte[1024];
        var result = gcm.processBytes(message, 0, message.length, output, 0);
        var result1 = gcm.doFinal(output, result);
        return Arrays.copyOfRange(output, 0, result + result1);
    }

    private static byte[] decipher(byte[] message) throws Throwable {
        var gcm = GCMBlockCipher.newInstance(AESEngine.newInstance());
        gcm.init(false, new ParametersWithIV(new KeyParameter(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), new byte[12]));
        var output = new byte[1024];
        var result = gcm.processBytes(message, 0, message.length, output, 0);
        var result1 = gcm.doFinal(output, result);
        return Arrays.copyOfRange(output, 0, result + result1);
    }
}
