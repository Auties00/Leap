package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.mac.TlsExchangeMac;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Security;

public final class CCMMode extends TlsCipherMode.Block {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final TlsCipherModeFactory FACTORY = CCMMode::new;

    private CCMMode(TlsCipherEngine engine) {
        super(engine);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        super.init(forEncryption, key, fixedIv, authenticator);
        engine.init(forEncryption, key);
    }

    @Override
    public void encrypt(TlsContext context, TlsMessage message, ByteBuffer output) {
        var input = output.duplicate();
        message.serializeMessage(input);

        var iv = new byte[ivLength()];
        System.arraycopy(fixedIv, 0, iv, 0, fixedIv.length);
        var nonce = authenticator.sequenceNumber();
        System.arraycopy(nonce, 0, iv, fixedIv.length, nonce.length);
        output.put(output.position() - nonce.length, nonce);
        var offset = nonce.length;

        var outputPosition = output.position();
        try {
            var temp = Cipher.getInstance("AES/CCM/NoPadding", "BC");
            temp.init(engine.forEncryption() ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(engine.key(), "AES"), new AEADParameterSpec(iv, 16 * 8));
            var aad = authenticator.createAuthenticationBlock(message.contentType().id(), input.remaining() - (engine.forEncryption() ? 0 : tagLength()), null);
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
        var output = input.duplicate();
        var iv = new byte[ivLength()];
        var offset = 0;
        System.arraycopy(fixedIv, 0, iv, 0, fixedIv.length);
        input.get(iv, fixedIv.length, dynamicIvLength());


        var outputPosition = output.position();
        try {
            var temp = Cipher.getInstance("AES/CCM/NoPadding", "BC");
            temp.init(engine.forEncryption() ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(engine.key(), "AES"), new AEADParameterSpec(iv, 16 * 8));
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
