package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.cipher.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

public final class DESEdeEngine extends DESBaseEngine {
    private static final int BLOCK_SIZE = 8;
    private static final TlsCipherEngineFactory FACTORY = DESEdeEngine::new;

    private int[] workingKey1;
    private int[] workingKey2;
    private int[] workingKey3;

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        super.init(forEncryption, key);
        var key1 = new byte[8];
        System.arraycopy(key, 0, key1, 0, key1.length);
        this.workingKey1 = generateWorkingKey(forEncryption, key1);
        var key2 = new byte[8];
        System.arraycopy(key, 8, key2, 0, key2.length);
        this.workingKey2 = generateWorkingKey(!forEncryption, key2);
        this.workingKey3 = workingKey1;
    }

    @Override
    public int blockLength() {
        return BLOCK_SIZE;
    }

    @Override
    public void update(ByteBuffer input, ByteBuffer output) {
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
