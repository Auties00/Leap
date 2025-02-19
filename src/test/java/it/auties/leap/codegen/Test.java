package it.auties.leap.codegen;

import it.auties.leap.tls.cipher.engine.implementation.ChaCha20Engine;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Test {
    public static void main(String[] args) throws Throwable {
        var message = new byte[16];
        System.out.println(Arrays.toString(cipher(message)));
        System.out.println(Arrays.toString(decipher(message)));;
    }

    private static byte[] cipher(byte[] message) throws Throwable {
        var gcm = new ChaCha20Engine();
        gcm.init(true, new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
        var output = ByteBuffer.allocate(1024);
        gcm.cipher(ByteBuffer.wrap(message), output);
        return Arrays.copyOfRange(output.array(), output.position(), output.limit());
    }

    private static byte[] decipher(byte[] message) {
        var gcm = new ChaCha7539Engine();
        gcm.init(true, new ParametersWithIV(new KeyParameter(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), new byte[12]));
        var output = new byte[1024];
        var result = gcm.processBytes(message, 0, message.length, output, 0);
        return Arrays.copyOfRange(output, 0, result);
    }
}
