package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.cipher.mode.TlsCipher;
import it.auties.leap.tls.cipher.mode.TlsCipherFactory;
import it.auties.leap.tls.cipher.mode.TlsCipherWithEngineFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.util.BufferUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public final class CbcCipher extends TlsCipher.Block {
    private static final TlsCipherFactory FACTORY = (factory) -> new TlsCipherWithEngineFactory() {
        @Override
        public TlsCipher newCipher(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
            var engine = factory.newCipherEngine(forEncryption, key);
            return new CbcCipher(engine, fixedIv, authenticator);
        }

        @Override
        public int ivLength() {
            return factory.blockLength();
        }

        @Override
        public int fixedIvLength() {
            return 0;
        }

        @Override
        public int tagLength() {
            return 0;
        }
    };

    private ByteBuffer cbcV;
    private ByteBuffer cbcNextV;

    private CbcCipher(TlsCipherEngine engine, byte[] fixedIv, TlsExchangeMac authenticator) {
        super(engine, fixedIv, authenticator);
        this.cbcV = ByteBuffer.allocate(engine().blockLength());
        if(fixedIv != null) {
            cbcV.put(0, fixedIv);
        }
        this.cbcNextV = ByteBuffer.allocate(engine().blockLength());
    }

    public static TlsCipherFactory factory() {
        return FACTORY;
    }

    @Override
    public void encrypt(TlsContext context, TlsMessage message, ByteBuffer output) {
        switch (authenticator.version()) {
            case TLS10, DTLS10, SSL30 -> throw new UnsupportedOperationException();
            case TLS11, TLS12, DTLS12 -> tls11Encrypt(message, output);
            case TLS13, DTLS13 -> throw new TlsAlert("CBC ciphers are not allowed in (D)TLSv1.3");
        };
    }

    private void tls11Encrypt(TlsMessage message, ByteBuffer output) {
        var input = output.duplicate();
        message.serialize(input);
        addMac(input, message.contentType().id());
        var nonce = new byte[engine().blockLength()];
        try {
            SecureRandom.getInstanceStrong()
                    .nextBytes(nonce);
        }catch (NoSuchAlgorithmException _) {
            throw TlsAlert.noSecureRandom();
        }
        System.out.println("IV: " + Arrays.toString(nonce));
        var inputPositionWithNonce = input.position() - nonce.length;
        input.put(inputPositionWithNonce, nonce);
        input.position(inputPositionWithNonce);
        if(BufferUtils.equals(input, output)) {
            output.position(inputPositionWithNonce);
        }
        var plaintextLength = addPadding(input);
        if(plaintextLength != encryptBlock(input, output)) {
            throw new TlsAlert("Unexpected number of plaintext bytes");
        }
    }

    @Override
    public ByteBuffer decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input) {
        return switch (authenticator.version()) {
            case TLS10, DTLS10, SSL30 -> throw new UnsupportedOperationException();
            case TLS11, TLS12, DTLS12 -> tls11Decrypt(metadata, input);
            case TLS13, DTLS13 -> throw new TlsAlert("CBC ciphers are not allowed in (D)TLSv1.3");
        };
    }

    private ByteBuffer tls11Decrypt(TlsMessageMetadata metadata, ByteBuffer input) {
        var output = input.duplicate();
        var cipheredLength = input.remaining();
        if(cipheredLength != decryptBlock(input, output)) {
            throw new TlsAlert("Unexpected number of ciphered bytes");
        }
        removePadding(output);
        checkCbcMac(output, metadata.contentType().id(), null);
        return output;
    }

    private int addPadding(ByteBuffer bb) {
        var len = bb.remaining();
        var offset = bb.position();

        var newlen = len + 1;
        if ((newlen % engine().blockLength()) != 0) {
            newlen += engine().blockLength() - 1;
            newlen -= newlen % engine().blockLength();
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
            throw new TlsAlert("Padding length should be positive");
        }

        if (authenticator.version() == TlsVersion.SSL30) {
            if (padValue > engine().blockLength()) {
                throw new TlsAlert("Padding length (" + padValue + ") of SSLv3 message should not be bigger than the block size (" + engine().blockLength() + ")");
            }
        }else {
            while (toCheck.hasRemaining()) {
                if (toCheck.get() != padValue) {
                    throw new TlsAlert("Invalid TLS padding data");
                }
            }
        }

        output.limit(offset + newLen);
    }

    private int encryptBlock(ByteBuffer input, ByteBuffer output) {
        var initialPosition = output.position();
        var blockLength = engine().blockLength();
        for (var i = 0; i < blockLength; i++) {
            cbcV.put(i, (byte) (cbcV.get(i) ^ input.get()));
        }
        engine.cipher(cbcV.position(0), output);
        while (input.hasRemaining()) {
            for (var i = 0; i < blockLength; i++) {
                cbcV.put(i, (byte) (output.get(output.position() - blockLength + i) ^ input.get()));
            }
            engine.cipher(cbcV.position(0), output);
        }
        var result = output.position() - initialPosition;
        output.limit(output.position());
        output.position(initialPosition);
        return result;
    }

    private int decryptBlock(ByteBuffer input, ByteBuffer output) {
        var initialPosition = output.position();
        var blockLength = engine().blockLength();
        while (input.hasRemaining()) {
            var blockPosition = output.position();

            for(var i = 0; i < blockLength; i++) {
                cbcNextV.put(i, input.get(input.position() + i));
            }

            engine.cipher(input, output);

            for (int i = 0; i < blockLength; i++) {
                var position = blockPosition + i;
                output.put(position, (byte) (output.get(position) ^ cbcV.get(i)));
            }

            var tmp = cbcV;
            cbcV = cbcNextV;
            cbcNextV = tmp;
        }

        var result = output.position() - initialPosition;
        output.limit(output.position());
        output.position(initialPosition + blockLength);

        return result;
    }

    @Override
    public int ivLength() {
        return engine().blockLength();
    }

    @Override
    public int fixedIvLength() {
        return 0;
    }

    @Override
    public int tagLength() {
        return 0;
    }
}
