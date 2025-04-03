package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;
import it.auties.leap.tls.cipher.mode.TlsCipher;
import it.auties.leap.tls.cipher.mode.TlsCipherFactory;
import it.auties.leap.tls.cipher.mode.TlsCipherWithEngineFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.scopedWrite;

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
    public void encrypt(TlsContext context, TlsMessage message, ByteBuffer output) {
        var input = output.duplicate();
        try(var _ = scopedWrite(input, message.length(), true)) {
            message.serialize(input);
        }

        addMac(input, message.contentType().id());
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
