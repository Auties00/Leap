package it.auties.leap.tls.cipher.engine.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public class DESEngine extends DESBaseEngine {
    private static final TlsCipherEngineFactory FACTORY = DESEngine::new;

    private int[] workingKey;

    private DESEngine() {
        super(8);
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        super.init(forEncryption, key);
        this.workingKey = generateWorkingKey(forEncryption, key);
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void cipher(ByteBuffer input, ByteBuffer output) {
        desFunc(input, output, workingKey);
    }
}
