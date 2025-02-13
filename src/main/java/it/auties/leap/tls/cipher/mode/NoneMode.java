package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.*;

import java.nio.ByteBuffer;

public final class NoneMode extends TlsCipherMode.Block {
    private static final NoneMode INSTANCE = new NoneMode();
    private static final TlsCipherModeFactory FACTORY = () -> INSTANCE;

    public static NoneMode instance() {
        return INSTANCE;
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        super.init(authenticator, engine, fixedIv);
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
    public TlsCipherIV ivLength() {
        return TlsCipherIV.none();
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
