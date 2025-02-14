package it.auties.leap.integrity;

import it.auties.leap.tls.cipher.TlsExchangeAuthenticator;
import it.auties.leap.tls.cipher.engine.AESEngine;
import it.auties.leap.tls.cipher.mode.GCMMode;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.version.TlsVersion;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class EngineIntegrity {
    public static void main(String[] args) throws Throwable {
        // Define a 128-bit key (16 bytes)
        byte[] keyBytes = new byte[] {
                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };

        // Define a 16-byte plaintext block
        byte[] plaintext = new byte[] {
                (byte)0x32, (byte)0x43, (byte)0xf6, (byte)0xa8,
                (byte)0x88, (byte)0x5a, (byte)0x30, (byte)0x8d,
                (byte)0x31, (byte)0x31, (byte)0x98, (byte)0xa2,
                (byte)0xe0, (byte)0x37, (byte)0x07, (byte)0x34
        };

        // Create an instance of AESEngine
        var aesEngine = Cipher.getInstance("AES/GCM/NoPadding");

        // Initialize the engine for encryption.
        // The 'true' parameter indicates encryption mode.
        aesEngine.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new GCMParameterSpec(96, new byte[12]));
aesEngine.updateAAD(new byte[13]);
        // Prepare an output buffer for the ciphertext
        byte[] ciphertext = new byte[1024];

        // Encrypt the plaintext block.
        // processBlock(input, inOff, output, outOff)
        var cipherLength = aesEngine.doFinal(plaintext, 0, plaintext.length, ciphertext, 0);


        System.out.println(Arrays.toString(Arrays.copyOfRange(ciphertext, 0, cipherLength)));

        var aesEngine1 = new AESEngine();
        aesEngine1.init(true, keyBytes);
        var gcm = new GCMMode(aesEngine1);
        gcm.init(TlsExchangeAuthenticator.of(TlsVersion.TLS12, TlsHashFactory.sha1(), new byte[32]), new byte[4]);
        var output = ByteBuffer.allocate(1024);
        gcm.update(TlsMessage.ContentType.APPLICATION_DATA.id(), ByteBuffer.wrap(plaintext), output, null);
        output.flip();
        System.out.println(Arrays.toString(Arrays.copyOfRange(output.array(), 0, output.limit())));
    }
}
