package it.auties.leap.tls.crypto.cipher.engine;

import java.nio.ByteBuffer;

final class DESedeEngine extends DESEngine {
    private static final int BLOCK_SIZE = 8;

    private final int[] workingKey1;
    private final int[] workingKey2;
    private final int[] workingKey3;
    DESedeEngine(boolean forEncryption, byte[] key) {
        super(forEncryption, key);

        byte[] key1 = new byte[8];
        System.arraycopy(key, 0, key1, 0, key1.length);
        workingKey1 = generateWorkingKey(forEncryption, key1);

        byte[] key2 = new byte[8];
        System.arraycopy(key, 8, key2, 0, key2.length);
        workingKey2 = generateWorkingKey(!forEncryption, key2);

        if (key.length == 24) {
            byte[] key3 = new byte[8];
            System.arraycopy(key, 16, key3, 0, key3.length);
            workingKey3 = generateWorkingKey(forEncryption, key3);
        } else {
            workingKey3 = workingKey1;
        }
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public void process(ByteBuffer input, ByteBuffer output) {
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
