package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.cipher.TlsCipherEngine;
import it.auties.leap.tls.cipher.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public final class RC4Engine extends TlsCipherEngine.Stream {
    private final static int STATE_LENGTH = 256;
    private static final TlsCipherEngineFactory FACTORY_40 = () -> new RC4Engine(5);
    private static final TlsCipherEngineFactory FACTORY_128 = () -> new RC4Engine(16);

    private byte[] engineState;
    private int x;
    private int y;

    public RC4Engine(int keyLength) {
        super(keyLength);
    }

    public static TlsCipherEngineFactory factory40() {
        return FACTORY_40;
    }

    public static TlsCipherEngineFactory factory128() {
        return FACTORY_128;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        super.init(forEncryption, key);
        this.engineState = new byte[STATE_LENGTH];
        for (int i = 0; i < STATE_LENGTH; i++) {
            engineState[i] = (byte) i;
        }

        var i1 = 0;
        var i2 = 0;
        for (var i = 0; i < STATE_LENGTH; i++) {
            i2 = ((key[i1] & 0xff) + engineState[i] + i2) & 0xff;
            var tmp = engineState[i];
            engineState[i] = engineState[i2];
            engineState[i2] = tmp;
            i1 = (i1 + 1) % key.length;
        }
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output) {
        var len = input.remaining();
        for (var i = 0; i < len; i++) {
            x = (x + 1) & 0xff;
            y = (engineState[x] + y) & 0xff;

            var tmp = engineState[x];
            engineState[x] = engineState[y];
            engineState[y] = tmp;

            output.put((byte) (input.get() ^ engineState[(engineState[x] + engineState[y]) & 0xff]));
        }
    }
}
