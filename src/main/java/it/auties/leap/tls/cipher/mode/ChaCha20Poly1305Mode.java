package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.message.TlsMessage;

import java.nio.ByteBuffer;

// Why didn't I implement ChaCha20Poly1305Mode like the other ciphers?
//  - Java already supports ChaCha20Poly1305
//  - While AES is ChaCha20Poly1305Mode supported out of the box, it makes sense to write an engine for that because we can apply it to CBC, CCM, GCM while here we can't
final class ChaCha20Poly1305Mode extends TlsCipherMode.Stream implements TlsCipherMode.AEAD {
    @Override
    public void update(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {

    }

    @Override
    public void doFinal(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {

    }

    @Override
    public void reset() {

    }

    @Override
    public int nonceLength() {
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
