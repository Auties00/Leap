package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.util.BufferHelper;

import java.nio.ByteBuffer;

final class MagmaEngine extends TlsCipherEngine.Block {
    private static final int BLOCK_SIZE = 8;
    private static final byte[] S_BOX_DEFAULT = {0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3, 0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9, 0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB, 0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3, 0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2, 0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE, 0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC, 0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC};

    private int[] workingKey;
    MagmaEngine() {
        super(8, 32);
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        if(workingKey != null) {
            throw new IllegalStateException();
        }

        if(key.length != keyLength) {
            throw new IllegalArgumentException();
        }

        this.forEncryption = forEncryption;
        this.workingKey = generateWorkingKey(key);
    }

    private int[] generateWorkingKey(byte[] key) {
        var workingKey = new int[8];
        workingKey[0] = BufferHelper.readBigEndianInt32(key, 0);
        workingKey[1] = BufferHelper.readBigEndianInt32(key, 4);
        workingKey[2] = BufferHelper.readBigEndianInt32(key, 8);
        workingKey[3] = BufferHelper.readBigEndianInt32(key, 12);
        workingKey[4] = BufferHelper.readBigEndianInt32(key, 16);
        workingKey[5] = BufferHelper.readBigEndianInt32(key, 20);
        workingKey[6] = BufferHelper.readBigEndianInt32(key, 24);
        workingKey[7] = BufferHelper.readBigEndianInt32(key, 28);
        return workingKey;
    }

    @Override
    public int blockLength() {
        return BLOCK_SIZE;
    }

    @Override
    public void process(ByteBuffer input, ByteBuffer output) {
        if(workingKey == null) {
            throw new IllegalStateException();
        }

        var n1 = BufferHelper.readBigEndianInt32(input);
        var n2 = BufferHelper.readBigEndianInt32(input);

        int tmp;
        if (this.forEncryption) {
            for (var k = 0; k < 3; k++) {
                for (var j = 0; j < 8; j++) {
                    tmp = n1;
                    n1 = n2 ^ mainStep(n1, workingKey[j]);
                    n2 = tmp;
                }
            }
            for (var j = 7; j > 0; j--) {
                tmp = n1;
                n1 = n2 ^ mainStep(n1, workingKey[j]);
                n2 = tmp;
            }
        } else {
            for (var j = 0; j < 8; j++) {
                tmp = n1;
                n1 = n2 ^ mainStep(n1, workingKey[j]);
                n2 = tmp;
            }
            for (var k = 0; k < 3; k++) {
                for (var j = 7; j >= 0; j--) {
                    if ((k == 2) && (j == 0)) {
                        break;
                    }
                    tmp = n1;
                    n1 = n2 ^ mainStep(n1, workingKey[j]);
                    n2 = tmp;
                }
            }
        }

        n2 = n2 ^ mainStep(n1, workingKey[0]);

        BufferHelper.writeBigEndianInt32(output, n1);
        BufferHelper.writeBigEndianInt32(output, n2);
    }

    private int mainStep(int n1, int key) {
        var cm = key + n1;
        int om = S_BOX_DEFAULT[((cm >> (0)) & 0xF)]
                + (S_BOX_DEFAULT[32 + ((cm >> (2 * 4)) & 0xF)] << 8)
                + (S_BOX_DEFAULT[48 + ((cm >> (3 * 4)) & 0xF)] << 12)
                + (S_BOX_DEFAULT[64 + ((cm >> (4 * 4)) & 0xF)] << 16)
                + (S_BOX_DEFAULT[80 + ((cm >> (5 * 4)) & 0xF)] << 20)
                + (S_BOX_DEFAULT[96 + ((cm >> (6 * 4)) & 0xF)] << 24)
                + (S_BOX_DEFAULT[112 + ((cm >> (7 * 4)) & 0xF)] << 28);
        return om << 11 | om >>> 21;
    }

    @Override
    public void reset() {
        if(workingKey == null) {
            throw new IllegalStateException();
        }
    }
}
