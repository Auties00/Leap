package it.auties.leap.integrity;

import it.auties.leap.tls.cipher.TlsExchangeAuthenticator;
import it.auties.leap.tls.cipher.mode.CBCMode;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.version.TlsVersion;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;

public class EngineIntegrity {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        var key = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        var message = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        var cipher = new DefaultBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()));
        cipher.init(true, new KeyParameter(key));
        var output = new byte[1024];
        var result = cipher.processBytes(message, 0, message.length, output, 0);
        System.out.println(Arrays.toString(Arrays.copyOfRange(output, 0, result)));
        var cipher1 = new CBCMode(new it.auties.leap.tls.cipher.engine.AESEngine(16));
        cipher1.engine().init(true, key);
        var output1 = ByteBuffer.allocate(1024).limit(512);
        cipher1.init(TlsExchangeAuthenticator.of(TlsVersion.TLS12, TlsHashFactory.sha384(), new byte[0]), null);
        cipher1.update((byte) 1, ByteBuffer.wrap(message), output1, null);
        System.out.println(Arrays.toString(Arrays.copyOfRange(output1.array(), output1.position(), output1.limit())));
    }
}
