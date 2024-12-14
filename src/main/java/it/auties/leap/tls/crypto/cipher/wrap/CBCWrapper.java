package it.auties.leap.tls.crypto.cipher.wrap;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsSpecificationException;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.crypto.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.crypto.key.TlsSessionKeys;
import it.auties.leap.tls.message.TlsMessage.ContentType;

import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import static it.auties.leap.tls.crypto.cipher.TlsCipherEngine.Mode.*;

final class CBCWrapper extends TlsCipherWrapper {
    private static final int BLOCK_SIZE = 16;

    private final boolean reducedKeySize;
    private final SecureRandom random;
    private TlsCipherEngine writeCipher;
    private TlsCipherEngine readCipher;

    CBCWrapper(TlsVersion version, TlsCipher cipher, TlsExchangeAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsEngineMode mode, boolean reducedKeySize) {
        super(version, cipher, authenticator, sessionKeys, mode);
        this.reducedKeySize = reducedKeySize;
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
            this.writeCipher = TlsCipherEngine.of(cipher, WRITE, createIv(), sessionKeys, null);
        }

        addMac(input, contentType.id());

        var nonce = new byte[BLOCK_SIZE];
        random.nextBytes(nonce);
        var inputPositionWithNonce = input.position() - nonce.length;
        input.put(inputPositionWithNonce, nonce);
        input.position(inputPositionWithNonce);

        var plaintextLength = addPadding(input);
        if(plaintextLength != writeCipher.wrap(input, output, false)) {
            throw new RuntimeException("Unexpected number of plaintext bytes");
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
            this.readCipher = TlsCipherEngine.of(cipher, READ, createIv(), sessionKeys, null);
        }

        var cipheredLength = input.remaining();
        var outputPosition = output.position();
        if(cipheredLength != readCipher.unwrap(input, output, false)) {
            throw new RuntimeException("Unexpected number of ciphered bytes");
        }
        output.limit(output.position());
        output.position(outputPosition + BLOCK_SIZE);
        removePadding(output);
        checkCbcMac(output, contentType.id(), sequence);
    }

    private IvParameterSpec createIv() {
        var iv = new byte[cipher.type().ivLength()];
        return new IvParameterSpec(iv);
    }

    private int addPadding(ByteBuffer bb) {
        var len = bb.remaining();
        var offset = bb.position();

        var newlen = len + 1;
        if ((newlen % CBCWrapper.BLOCK_SIZE) != 0) {
            newlen += CBCWrapper.BLOCK_SIZE - 1;
            newlen -= newlen % CBCWrapper.BLOCK_SIZE;
        }

        var pad = (byte) (newlen - len);

        bb.limit(newlen + offset);

        offset += len;
        for (var i = 0; i < pad; i++) {
            bb.put(offset++, (byte) (pad - 1));
        }

        return newlen;
    }

    private void removePadding(ByteBuffer output) {
        var len = output.remaining();
        var offset = output.position();

        var padOffset = offset + len - 1;
        var padValue = output.get(padOffset);
        var newLen = len - Byte.toUnsignedInt(padValue) - 1;

        var toCheck = output.duplicate()
                .position(offset + newLen);
        if(!toCheck.hasRemaining()) {
            throw new RuntimeException("Padding length should be positive");
        }

        if (version == TlsVersion.SSL30) {
            if (padValue > CBCWrapper.BLOCK_SIZE) {
                throw new RuntimeException("Padding length (" + padValue + ") of SSLv3 message should not be bigger than the block size (" + CBCWrapper.BLOCK_SIZE + ")");
            }
        }else {
            while (toCheck.hasRemaining()) {
                if (toCheck.get() != padValue) {
                    throw new RuntimeException("Invalid TLS padding data");
                }
            }
        }

        output.limit(offset + newLen);
    }

    @Override
    public int nonceLength() {
        return BLOCK_SIZE;
    }
}
