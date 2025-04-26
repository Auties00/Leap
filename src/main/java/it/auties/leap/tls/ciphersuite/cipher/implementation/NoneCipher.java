package it.auties.leap.tls.ciphersuite.cipher.implementation;

import it.auties.leap.tls.ciphersuite.exchange.TlsExchangeMac;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipher;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipherFactory;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipherWithEngineFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class NoneCipher extends TlsCipher.Block {
    private static final TlsCipherFactory FACTORY = _ -> new TlsCipherWithEngineFactory() {
        @Override
        public TlsCipher newCipher(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
            return new NoneCipher(authenticator);
        }

        @Override
        public int ivLength() {
            return 0;
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

    private NoneCipher(TlsExchangeMac authenticator) {
        super(null, null, authenticator);
    }

    public static TlsCipherFactory factory() {
        return FACTORY;
    }

    @Override
    public void encrypt(byte contentType, ByteBuffer input, ByteBuffer output) {


        addMac(input, contentType);
        move(input, output);
    }

    @Override
    public ByteBuffer decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input) {
        var output = input.duplicate()
                .limit(input.capacity());
        addMac(input, metadata.contentType().id());
        move(input, output);
        return output;
    }

    @Override
    public int ivLength() {
        return 0;
    }

    @Override
    public int fixedIvLength() {
        return 0;
    }

    @Override
    public int tagLength() {
        return 0;
    }

    private void move(ByteBuffer input, ByteBuffer output) {
        var outputPosition = output.position();
        output.put(input)
                .limit(output.position())
                .position(outputPosition);
    }
}
