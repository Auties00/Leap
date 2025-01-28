package it.auties.leap.tls.cipher.mode.implementation;

import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;

import java.nio.ByteBuffer;

public final class NoneMode extends TlsCipherMode.Block {
    private static final NoneMode INSTANCE = new NoneMode();
    private static final TlsCipherModeFactory FACTORY = (_, _, _, _) -> INSTANCE;

    public static NoneMode instance() {
        return INSTANCE;
    }

    private NoneMode() {
        super(null, null, null, new byte[0]);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        addMac(input, contentType);
        move(input, output);
    }

    @Override
    public void doFinal(byte contentType, ByteBuffer input, ByteBuffer output) {
        addMac(input, contentType);
        move(input, output);
    }

    @Override
    public void reset() {

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
