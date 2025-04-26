package it.auties.leap.tls.ciphersuite.engine.implementation;

import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngine;
import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public final class DesEdeEngine extends DesBaseEngine {
    private static final int BLOCK_SIZE = 8;
    private static final TlsCipherEngineFactory FACTORY = new TlsCipherEngineFactory() {
        @Override
        public TlsCipherEngine newCipherEngine(boolean forEncryption, byte[] key) {
            if (key == null || key.length != keyLength()) {
                throw new IllegalArgumentException("Invalid key length");
            }

            return new DesEdeEngine(forEncryption, key);
        }

        @Override
        public int keyLength() {
            return 24;
        }

        @Override
        public int blockLength() {
            return BLOCK_SIZE;
        }
    };

    private final int[] workingKey1;
    private final int[] workingKey2;
    private final int[] workingKey3;

    private DesEdeEngine(boolean forEncryption, byte[] key) {
        super(forEncryption);
        var key1 = new byte[8];
        System.arraycopy(key, 0, key1, 0, key1.length);
        this.workingKey1 = generateWorkingKey(forEncryption, key1);
        var key2 = new byte[8];
        System.arraycopy(key, 8, key2, 0, key2.length);
        this.workingKey2 = generateWorkingKey(!forEncryption, key2);
        this.workingKey3 = workingKey1;
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public int blockLength() {
        return BLOCK_SIZE;
    }

    @Override
    public void cipher(ByteBuffer input, ByteBuffer output) {
        var temp = ByteBuffer.allocate(BLOCK_SIZE);
        if (forEncryption) {
            desFunc(input, output, workingKey1);
            desFunc(input, temp, workingKey2);
            temp.flip();
            desFunc(temp, output, workingKey3);
        } else {
            desFunc(input, output, workingKey3);
            desFunc(input, temp, workingKey2);
            temp.flip();
            desFunc(temp, output, workingKey1);
        }
    }
}
