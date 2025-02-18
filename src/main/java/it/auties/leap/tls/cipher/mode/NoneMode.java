package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.*;
import it.auties.leap.tls.mac.TlsExchangeMac;

import java.nio.ByteBuffer;

public final class NoneMode extends TlsCipherMode.Block {
    private static final NoneMode INSTANCE = new NoneMode();
    private static final TlsCipherModeFactory FACTORY = (_) -> INSTANCE;

    public NoneMode() {
        super(null);
    }

    public static NoneMode instance() {
        return INSTANCE;
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator) {
        super.init(forEncryption, key, fixedIv, authenticator);
    }

    @Override
    public void cipher(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
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
