package it.auties.leap.tls.cipher.engine;

import java.nio.ByteBuffer;

final class DESEdeEngine extends DESEngine {
    private static final int BLOCK_SIZE = 8;

    private int[] workingKey1;
    private int[] workingKey2;
    private int[] workingKey3;
    DESEdeEngine(int keyLength) {
        super(keyLength);
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        if(workingKey1 != null) {
            throw new IllegalStateException();
        }

        if(key.length != keyLength) {
            throw new IllegalArgumentException();
        }

        this.forEncryption = forEncryption;
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
    public void process(ByteBuffer input, ByteBuffer output) {
        if(workingKey3 == null) {
            throw new IllegalStateException();
        }

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

    @Override
    public void reset() {
        if(workingKey3 == null) {
            throw new IllegalStateException();
        }
    }
}
