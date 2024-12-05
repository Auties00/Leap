package it.auties.leap.tls.encryption.mode;

import it.auties.leap.tls.TlsCipher.Type;
import it.auties.leap.tls.TlsSpecificationException;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.encryption.TlsEncryption;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.auth.TlsAuthenticator;
import it.auties.leap.tls.key.TlsSessionKeys;
import it.auties.leap.tls.message.TlsMessage.ContentType;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public final class Ccm extends TlsEncryption {
    private static final int BLOCK_SIZE = 16;

    private Cipher writeCipher;
    private Cipher readCipher;
    private final SecureRandom random;

    public Ccm(TlsVersion version, Type type, TlsAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsEngineMode mode) {
        super(version, type, authenticator, sessionKeys, mode);
        this.random = new SecureRandom();
    }

    @Override
    public void encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        switch (version) {
            case TLS10, DTLS10 -> throw new UnsupportedOperationException();
            case TLS11, TLS12, DTLS12 -> tls11Encrypt(contentType, input, output);
            case TLS13, DTLS13 -> throw new TlsSpecificationException("AesCbc ciphers are not allowed in (D)TLSv1.3");
        }
    }

    private void tls11Encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        if(writeCipher == null) {
            writeCipher = createCipher(Mode.WRITE);
        }

        addMac(input, contentType.id());

        var nonce = new byte[BLOCK_SIZE];
        random.nextBytes(nonce);
        var inputPositionWithNonce = input.position() - nonce.length;
        input.put(inputPositionWithNonce, nonce);
        input.position(inputPositionWithNonce);

        var plaintextLength = addPadding(input);
        try {
            if(plaintextLength != writeCipher.update(input, output)) {
                throw new RuntimeException("Unexpected number of plaintext bytes");
            }
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot encrypt message", exception);
        }

        var outputLimit = output.position();
        output.limit(outputLimit);
        output.position(outputLimit - plaintextLength);
    }

    @Override
    public void decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        switch (version) {
            case TLS10, DTLS10 -> throw new UnsupportedOperationException();
            case TLS11, TLS12, DTLS12 -> tls11Decrypt(contentType, input, output, sequence);
            case TLS13, DTLS13 -> throw new TlsSpecificationException("BLOCK ciphers are not allowed in (D)TLSv1.3");
        }
    }

    private void tls11Decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        if(readCipher == null) {
            readCipher = createCipher(Mode.READ);
        }

        var cipheredLength = input.remaining();
        var outputPosition = output.position();
        try {
            if(cipheredLength != readCipher.update(input, output)) {
                throw new RuntimeException("Unexpected number of ciphered bytes");
            }
            output.limit(output.position());
            output.position(outputPosition + BLOCK_SIZE);
            removePadding(output);
            checkCBCMac(output, contentType.id(), sequence);
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot decrypt message", exception);
        }
    }

    private Cipher createCipher(Mode mode) {
        try {
            var iv = new byte[type.ivLength()];
            var cipher = Cipher.getInstance("AES/CCM/NoPadding");
            var key = switch (mode) {
                case READ -> sessionKeys.remoteCipherKey();
                case WRITE -> sessionKeys.localCipherKey();
            };
            var cipherMode = switch (mode) {
                case READ -> Cipher.DECRYPT_MODE;
                case WRITE -> Cipher.ENCRYPT_MODE;
            };
            cipher.init(
                    cipherMode,
                    key,
                    new IvParameterSpec(iv),
                    random
            );
            return cipher;
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot initialize CBC cipher", exception);
        }
    }

    private int addPadding(ByteBuffer bb) {
        var len = bb.remaining();
        var offset = bb.position();

        var newlen = len + 1;
        if ((newlen % Ccm.BLOCK_SIZE) != 0) {
            newlen += Ccm.BLOCK_SIZE - 1;
            newlen -= newlen % Ccm.BLOCK_SIZE;
        }

        var pad = (byte) (newlen - len);

        bb.limit(newlen + offset);

        offset += len;
        for (var i = 0; i < pad; i++) {
            bb.put(offset++, (byte) (pad - 1));
        }

        return newlen;
    }

    private void removePadding(ByteBuffer output) throws BadPaddingException {
        var len = output.remaining();
        var offset = output.position();

        var padOffset = offset + len - 1;
        var padValue = output.get(padOffset);
        var newLen = len - Byte.toUnsignedInt(padValue) - 1;

        var toCheck = output.duplicate()
                .position(offset + newLen);
        if(!toCheck.hasRemaining()) {
            throw new BadPaddingException("Padding length should be positive");
        }

        if (version == TlsVersion.SSL30) {
            if (padValue > Ccm.BLOCK_SIZE) {
                throw new BadPaddingException("Padding length (" + padValue + ") of SSLv3 message should not be bigger than the block size (" + Ccm.BLOCK_SIZE + ")");
            }
        }else {
            while (toCheck.hasRemaining()) {
                if (toCheck.get() != padValue) {
                    throw new BadPaddingException("Invalid TLS padding data");
                }
            }
        }

        output.limit(offset + newLen);
    }

    @Override
    public int nonceLength() {
        return BLOCK_SIZE;
    }

    private enum Mode {
        WRITE,
        READ
    }
}
