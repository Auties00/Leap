package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

public final class NoneMode extends TlsCipherMode.Block {
    private static final NoneMode INSTANCE = new NoneMode();
    private static final TlsCipherModeFactory FACTORY = (_) -> INSTANCE;

    private NoneMode() {
        super(null);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void encrypt(TlsContext context, TlsMessage message, ByteBuffer output) {
        var input = output.duplicate();
        message.serializeMessage(input);
        addMac(input, message.contentType().id());
        move(input, output);
    }

    @Override
    public TlsMessage decrypt(TlsContext context, TlsMessageMetadata metadata, ByteBuffer input) {
        var output = input.duplicate();
        addMac(input, metadata.contentType().id());
        move(input, output);
        return TlsMessage.of(context, output, metadata.withMessageLength(output.remaining()));
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
