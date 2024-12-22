package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.message.TlsMessage;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

final class CBCMode extends TlsCipherMode.Block {
    private final SecureRandom random;
    private ByteBuffer cbcV;
    private ByteBuffer cbcNextV;
    CBCMode() {
        this.random = new SecureRandom();
    }

    @Override
    public void init(TlsVersion version, TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        super.init(version, authenticator, engine, fixedIv);
        this.cbcV = ByteBuffer.allocate(blockLength());
        this.cbcNextV = ByteBuffer.allocate(blockLength());
    }

    @Override
    public void update(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        switch (version) {
            case TLS10, DTLS10 -> throw new UnsupportedOperationException();
            case TLS11, TLS12, DTLS12 -> tls11Update(contentType, input, output, sequence);
            case TLS13, DTLS13 -> throw new TlsException("AesCbc ciphers are not allowed in (D)TLSv1.3");
        }
    }

    private void tls11Update(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        if (engine.forEncryption()) {
            addMac(input, contentType.id());
            var nonce = new byte[blockLength()];
            random.nextBytes(nonce);
            var inputPositionWithNonce = input.position() - nonce.length;
            input.put(inputPositionWithNonce, nonce);
            input.position(inputPositionWithNonce);

            var plaintextLength = addPadding(input);
            if(plaintextLength != encryptBlock(input, output)) {
                throw new RuntimeException("Unexpected number of plaintext bytes");
            }

            var outputLimit = output.position();
            output.limit(outputLimit);
            output.position(outputLimit - plaintextLength);
        }else {
            var cipheredLength = input.remaining();
            var outputPosition = output.position();
            if(cipheredLength != decryptBlock(input, output)) {
                throw new RuntimeException("Unexpected number of ciphered bytes");
            }
            output.limit(output.position());
            output.position(outputPosition + blockLength());
            removePadding(output);
            checkCbcMac(output, contentType.id(), sequence);
        }
    }

    private int addPadding(ByteBuffer bb) {
        var len = bb.remaining();
        var offset = bb.position();

        var newlen = len + 1;
        if ((newlen % blockLength()) != 0) {
            newlen += blockLength() - 1;
            newlen -= newlen % blockLength();
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
            if (padValue > blockLength()) {
                throw new RuntimeException("Padding length (" + padValue + ") of SSLv3 message should not be bigger than the block size (" + blockLength() + ")");
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
    public void doFinal(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {
       
    }

    private int encryptBlock(ByteBuffer input, ByteBuffer output) {
        var initialPosition = output.position();
        for (int i = 0; i < blockLength(); i++) {
            cbcV.put(i, (byte) (cbcV.get(i) ^ input.get()));
        }

        engine.process(cbcV, output);
        return output.position() - initialPosition;
    }

    private int decryptBlock(ByteBuffer input, ByteBuffer output) {
        var initialPosition = output.position();
        cbcNextV.clear();
        for(var i = 0; i < blockLength(); i++) {
            cbcNextV.put(input.get());
        }

        var outputPosition = output.position();
        engine.process(input, output);
        for (int i = 0; i < blockLength(); i++) {
            var position = outputPosition + i;
            output.put(position, (byte) (output.get(position) ^ cbcV.get(i)));
        }

        var tmp = cbcV;
        cbcV = cbcNextV;
        cbcNextV = tmp;
        return output.position() - initialPosition;
    }

    @Override
    public void reset() {
        cbcV.put(0, fixedIv);
        cbcNextV.clear();
        engine.reset();
    }

    @Override
    public int nonceLength() {
        return blockLength();
    }
}
