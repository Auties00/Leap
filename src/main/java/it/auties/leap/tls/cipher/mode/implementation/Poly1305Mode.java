package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

// Why didn't I implement ChaCha20Poly1305Mode like the other ciphers?
//  - Java already supports ChaCha20Poly1305
//  - While AES is ChaCha20Poly1305Mode supported out of the box, it makes sense to write an engine for that because we can apply it to CBC, CCM, GCM while here we can't
public final class Poly1305Mode extends TlsCipherMode.Stream {
    private static final TlsCipherModeFactory FACTORY = Poly1305Mode::new;
    public Poly1305Mode(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        super(version, authenticator, engine, fixedIv);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {

    }

    @Override
    public void doFinal(byte contentType, ByteBuffer input, ByteBuffer output) {

    }

    @Override
    public void reset() {

    }

    @Override
    public int tagLength() {
        return 0;
    }

    /*
    private final int mode;
    private final SecretKey secretKey;
    private final IvParameterSpec ivSpec;
    private final Cipher cipher;

    ChaCha20Poly1305Mode(boolean forEncryption, byte[] key, byte[] iv) {
        super(null, iv);
        try {
            this.mode = forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
            this.secretKey = new SecretKeySpec(key, "ChaCha20");
            this.ivSpec = new IvParameterSpec(iv);
            this.cipher = Cipher.getInstance("ChaCha20-Poly1305");
            reset();
        } catch (GeneralSecurityException exception) {
            throw new InternalError("Missing ChaCha20Poly1305 implementation");
        }
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output, boolean last) {
        try {
            if (last) {
                cipher.doFinal(input, output);
            } else {
                cipher.update(input, output);
            }
        } catch (GeneralSecurityException exception) {
            throw new InternalError("Cannot update engine", exception);
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
     */
}
