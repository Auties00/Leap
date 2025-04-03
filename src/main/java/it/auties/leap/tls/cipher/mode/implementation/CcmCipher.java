package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.cipher.mode.TlsCipher;
import it.auties.leap.tls.cipher.mode.TlsCipherFactory;
import it.auties.leap.tls.cipher.mode.TlsCipherWithEngineFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessageMetadata;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Security;

public final class CcmCipher extends TlsCipher.Block {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final TlsCipherFactory FACTORY = (factory) -> new TlsCipherWithEngineFactory() {
        @Override
        public TlsCipher newCipher(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
            var engine = factory.newCipherEngine(forEncryption, key);
            return new CcmCipher(engine, fixedIv, authenticator);
        }

        @Override
        public int ivLength() {
            return 12;
        }

        @Override
        public int fixedIvLength() {
            return 8;
        }

        @Override
        public int tagLength() {
            return factory.blockLength();
        }
    };

    private CcmCipher(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
        super(engine, fixedIv, authenticator);
    }

    public static TlsCipherFactory factory() {
        return FACTORY;
    }

    @Override
    public void encrypt(byte contentType, ByteBuffer output, ByteBuffer input) {
        var iv = new byte[ivLength()];
        System.arraycopy(fixedIv, 0, iv, 0, fixedIv.length);
        var nonce = authenticator.sequenceNumber();
        System.arraycopy(nonce, 0, iv, fixedIv.length, nonce.length);
        output.put(output.position() - nonce.length, nonce);
        var offset = nonce.length;

        var outputPosition = output.position();
        try {
            var temp = Cipher.getInstance("AES/CCM/NoPadding", "BC");
            temp.init(engine.forEncryption() ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(engineToKey(), "AES"), new AEADParameterSpec(iv, 16 * 8));
            var aad = authenticator.createAuthenticationBlock(contentType, input.remaining() - (engine.forEncryption() ? 0 : tagLength()), null);
            temp.updateAAD(aad, 0, aad.length);
            temp.doFinal(input, output);
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException(exception);
        }

        output.limit(output.position());
        output.position(outputPosition - offset);
    }

    @Override
    public ByteBuffer decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input) {
        var output = input.duplicate()
                .limit(input.capacity());
        var iv = new byte[ivLength()];
        var offset = 0;
        System.arraycopy(fixedIv, 0, iv, 0, fixedIv.length);
        input.get(iv, fixedIv.length, dynamicIvLength());


        var outputPosition = output.position();
        try {
            var temp = Cipher.getInstance("AES/CCM/NoPadding", "BC");
            temp.init(engine.forEncryption() ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(engineToKey(), "AES"), new AEADParameterSpec(iv, 16 * 8));
            var aad = authenticator.createAuthenticationBlock(metadata.contentType().id(), input.remaining() - (engine.forEncryption() ? 0 : tagLength()), null);
            temp.updateAAD(aad, 0, aad.length);
            temp.doFinal(input, output);
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException(exception);
        }

        output.limit(output.position());
        output.position(outputPosition - offset);

        return output;
    }

    private byte[] engineToKey() {
        // return engine.key();
        return null;
    }

    @Override
    public int ivLength() {
        return 12;
    }

    @Override
    public int fixedIvLength() {
        return 8;
    }

    @Override
    public int tagLength() {
        return engine().blockLength();
    }
}
