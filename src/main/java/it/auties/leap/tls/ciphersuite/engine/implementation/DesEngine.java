package it.auties.leap.tls.ciphersuite.engine.implementation;

import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngine;
import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public class DesEngine extends DesBaseEngine {
    private static final TlsCipherEngineFactory FACTORY = new TlsCipherEngineFactory() {
        @Override
        public TlsCipherEngine newCipherEngine(boolean forEncryption, byte[] key) {
            if (key == null || key.length != keyLength()) {
                throw new IllegalArgumentException("Invalid key length");
            }

            return new DesEngine(forEncryption, key);
        }

        @Override
        public int keyLength() {
            return 8;
        }

        @Override
        public int blockLength() {
            return BLOCK_SIZE;
        }
    };

    private final int[] workingKey;

    private DesEngine(boolean forEncryption, byte[] key) {
        super(forEncryption);
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
