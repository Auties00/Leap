package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.*;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.util.BufferUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

public final class CBCMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = CBCMode::new;

    private SecureRandom random;
    private ByteBuffer cbcV;
    private ByteBuffer cbcNextV;

    public CBCMode(TlsCipherEngine engine) {
        super(engine);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(TlsExchangeAuthenticator authenticator, byte[] fixedIv) {
        super.init(authenticator, fixedIv);
        this.cbcV = ByteBuffer.allocate(engine().blockLength());
        if(fixedIv != null) {
            cbcV.put(0, fixedIv);
        }
        this.cbcNextV = ByteBuffer.allocate(engine().blockLength());
        this.random = new SecureRandom();
    }

    @Override
    public void cipher(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        switch (authenticator.version()) {
            case TLS10, DTLS10 -> throw new UnsupportedOperationException();
            case TLS11, TLS12, DTLS12 -> tls11Update(contentType, input, output, sequence);
            case TLS13, DTLS13 -> throw new TlsException("CBC ciphers are not allowed in (D)TLSv1.3");
        }
    }

    private void tls11Update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        if (engine.forEncryption()) {
            addMac(input, contentType);
            var nonce = new byte[engine().blockLength()];
            random.nextBytes(nonce);
            var inputPositionWithNonce = input.position() - nonce.length;
            input.put(inputPositionWithNonce, nonce);
            input.position(inputPositionWithNonce);
            if(BufferUtils.equals(input, output)) {
                output.position(inputPositionWithNonce);
            }
            var plaintextLength = addPadding(input);
            if(plaintextLength != encryptBlock(input, output)) {
                throw new TlsException("Unexpected number of plaintext bytes");
            }
        }else {
            var cipheredLength = input.remaining();
            if(cipheredLength != decryptBlock(input, output)) {
                throw new TlsException("Unexpected number of ciphered bytes");
            }
            removePadding(output);
            checkCbcMac(output, contentType, sequence);
        }
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
            throw new RuntimeException("Padding length should be positive");
        }

        if (authenticator.version() == TlsVersion.SSL30) {
            if (padValue > engine().blockLength()) {
                throw new RuntimeException("Padding length (" + padValue + ") of SSLv3 message should not be bigger than the block size (" + engine().blockLength() + ")");
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
    public void reset() {
        if(fixedIv != null) {
            cbcV.put(0, fixedIv);
        }
        cbcNextV.clear();
    }

    @Override
    public TlsCipherIV ivLength() {
        return new TlsCipherIV(engine().blockLength(), 0);
    }

    @Override
    public int tagLength() {
        return 0;
    }
}
