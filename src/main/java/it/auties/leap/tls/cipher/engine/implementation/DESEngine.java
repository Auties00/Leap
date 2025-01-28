package it.auties.leap.tls.cipher.engine.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public class DESEngine extends DESBaseEngine {
    private static final TlsCipherEngineFactory FACTORY = DESEngine::new;

    private final int[] workingKey;

    public DESEngine(boolean forEncryption, byte[] key) {
        super(forEncryption, key);
        this.workingKey = generateWorkingKey(forEncryption, key);
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output) {
        desFunc(input, output, workingKey);
    }
}
