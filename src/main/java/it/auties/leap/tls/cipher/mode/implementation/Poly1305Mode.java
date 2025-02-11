package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.TlsCipherIV;
import it.auties.leap.tls.cipher.auth.TlsExchangeAuthenticator;
import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;

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

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    private int mode;
    private SecretKey secretKey;
    private IvParameterSpec ivSpec;
    private Cipher cipher;

    @Override
    public void init(TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        super.init(authenticator, engine, fixedIv);
        try {
            this.mode = engine.forEncryption() ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
            this.secretKey = new SecretKeySpec(engine.key(), "ChaCha20");
            this.ivSpec = new IvParameterSpec(fixedIv);
            this.cipher = Cipher.getInstance("ChaCha20-Poly1305");
            reset();
        } catch (GeneralSecurityException exception) {
            throw new InternalError("Missing ChaCha20Poly1305 implementation");
        }
    }

    @Override
    public void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        try {
            cipher.update(input, output);
        } catch (GeneralSecurityException exception) {
            throw new InternalError("Cannot update engine", exception);
        }
    }

    @Override
    public void doFinal(byte contentType, ByteBuffer input, ByteBuffer output) {
        try {
            cipher.doFinal(input, output);
        } catch (GeneralSecurityException exception) {
            throw new InternalError("Cannot doFinal engine", exception);
        }
    }

    @Override
    public void reset() {
        try {
            cipher.init(
                    mode,
                    secretKey,
                    ivSpec
            );
        } catch (GeneralSecurityException exception) {
            throw new InternalError("Cannot reset engine", exception);
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
