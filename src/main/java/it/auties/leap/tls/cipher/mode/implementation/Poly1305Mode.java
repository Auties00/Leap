package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.implementation.ChaCha20Engine;
import it.auties.leap.tls.cipher.mode.TlsCipherIV;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.mac.TlsExchangeMac;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

// Why didn't I implement ChaCha20Poly1305Mode like the other ciphers?
//  - Java already supports ChaCha20Poly1305
//  - While AES is ChaCha20Poly1305Mode supported out of the box, it makes sense to write an engine for that because we can apply it to CBC, CCM, GCM while here we can't
public final class Poly1305Mode extends TlsCipherMode.Stream {
    private static final TlsCipherModeFactory FACTORY = Poly1305Mode::new;

    public Poly1305Mode(TlsCipherEngine engine) {
        super(engine);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    private SecretKey secretKey;
    private Cipher cipher;

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        if(!(engine instanceof ChaCha20Engine)) {
            throw new TlsException("POLY1305 mode is supported only by ChaCha20 engines");
        }
        super.init(forEncryption, key, fixedIv, authenticator);
        try {
            engine.init(forEncryption, key);
            this.secretKey = new SecretKeySpec(key, "ChaCha20");
            this.cipher = Cipher.getInstance("ChaCha20-Poly1305");
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Missing ChaCha20Poly1305 implementation");
        }
    }

    @Override
    public void cipher(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        try {
            var initialPosition = output.position();
            if(engine.forEncryption()) {
                byte[] sn = authenticator.sequenceNumber();
                byte[] nonce = new byte[fixedIv.length];
                System.arraycopy(sn, 0, nonce, nonce.length - sn.length, sn.length);
                for (int i = 0; i < nonce.length; i++) {
                    nonce[i] ^= fixedIv[i];
                }
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        secretKey,
                        new IvParameterSpec(nonce)
                );
                byte[] aad = authenticator.createAuthenticationBlock(
                        contentType, input.remaining(), null);
                cipher.updateAAD(aad);
                cipher.doFinal(input, output);
            }else {
                byte[] sn = sequence;
                if (sn == null) {
                    sn = authenticator.sequenceNumber();
                }
                byte[] nonce = new byte[fixedIv.length];
                System.arraycopy(sn, 0, nonce, nonce.length - sn.length, sn.length);
                for (int i = 0; i < nonce.length; i++) {
                    nonce[i] ^= fixedIv[i];
                }

                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(nonce));

                // update the additional authentication data
                byte[] aad = authenticator.createAuthenticationBlock(contentType, input.remaining() - tagLength(), sequence);
                cipher.updateAAD(aad);

                cipher.doFinal(input, output);
            }
            output.limit(output.position());
            output.position(initialPosition);
        }catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot update poly1305", exception);
        }
    }

    @Override
    public TlsCipherIV ivLength() {
        return new TlsCipherIV(12, 0);
    }

    @Override
    public int tagLength() {
        return 16;
    }
}
