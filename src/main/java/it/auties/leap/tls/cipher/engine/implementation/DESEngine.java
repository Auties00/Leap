package it.auties.leap.tls.cipher.engine.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public class DESEngine extends DESBaseEngine {
    private static final TlsCipherEngineFactory FACTORY = new TlsCipherEngineFactory.Stream() {
        @Override
        public TlsCipherEngine newCipherEngine(boolean forEncryption, byte[] key) {
            return new DESEngine(forEncryption, key);
        }

        @Override
        public int keyLength() {
            return 8;
        }
    };

    private final int[] workingKey;

    private DESEngine(boolean forEncryption, byte[] key) {
        super(forEncryption, key);
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
