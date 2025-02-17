package it.auties.leap.tls.cipher.engine;

import it.auties.leap.tls.cipher.TlsCipherEngine;
import it.auties.leap.tls.cipher.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class IDEAEngine extends TlsCipherEngine.Block {
    private static final int BLOCK_SIZE = 8;
    private static final int MASK = 0xffff;
    private static final int BASE = 0x10001;
    private static final TlsCipherEngineFactory FACTORY = IDEAEngine::new;

    private int[] workingKey;

    public IDEAEngine() {
        super(16);
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        super.init(forEncryption, key);
        this.workingKey = forEncryption ? expandKey(key) : invertKey(expandKey(key));
    }

    private int[] invertKey(int[] inKey) {
        int t1, t2, t3, t4;
        int p = 52;
        int[] key = new int[52];
        int inOff = 0;

        t1 = mulInv(inKey[inOff++]);
        t2 = addInv(inKey[inOff++]);
        t3 = addInv(inKey[inOff++]);
        t4 = mulInv(inKey[inOff++]);
        key[--p] = t4;
        key[--p] = t3;
        key[--p] = t2;
        key[--p] = t1;

        for (int round = 1; round < 8; round++) {
            t1 = inKey[inOff++];
            t2 = inKey[inOff++];
            key[--p] = t2;
            key[--p] = t1;

            t1 = mulInv(inKey[inOff++]);
            t2 = addInv(inKey[inOff++]);
            t3 = addInv(inKey[inOff++]);
            t4 = mulInv(inKey[inOff++]);
            key[--p] = t4;
            key[--p] = t2;
            key[--p] = t3;
            key[--p] = t1;
        }

        t1 = inKey[inOff++];
        t2 = inKey[inOff++];
        key[--p] = t2;
        key[--p] = t1;

        t1 = mulInv(inKey[inOff++]);
        t2 = addInv(inKey[inOff++]);
        t3 = addInv(inKey[inOff++]);
        t4 = mulInv(inKey[inOff]);
        key[--p] = t4;
        key[--p] = t3;
        key[--p] = t2;
        key[--p] = t1;

        return key;
    }

    private int[] expandKey(byte[] userKey) {
        var key = new int[52];

        for (var i = 0; i < 8; i++) {
            key[i] = readBigEndianInt16(userKey, i * 2);
        }

        for (var i = 8; i < 52; i++) {
            if ((i & 7) < 6) {
                key[i] = ((key[i - 7] & 127) << 9 | key[i - 6] >> 7) & MASK;
            } else if ((i & 7) == 6) {
                key[i] = ((key[i - 7] & 127) << 9 | key[i - 14] >> 7) & MASK;
            } else {
                key[i] = ((key[i - 15] & 127) << 9 | key[i - 14] >> 7) & MASK;
            }
        }

        return key;
    }


    @Override
    public int blockLength() {
        return BLOCK_SIZE;
    }

    @Override
    public void cipher(ByteBuffer input, ByteBuffer output) {
        var keyOff = 0;
        var x0 = readBigEndianInt16(input);
        var x1 = readBigEndianInt16(input);
        var x2 = readBigEndianInt16(input);
        var x3 = readBigEndianInt16(input);
        for (var round = 0; round < 8; round++) {
            x0 = mul(x0, workingKey[keyOff++]);
            x1 += workingKey[keyOff++];
            x1 &= MASK;
            x2 += workingKey[keyOff++];
            x2 &= MASK;
            x3 = mul(x3, workingKey[keyOff++]);

            var t0 = x1;
            var t1 = x2;
            x2 ^= x0;
            x1 ^= x3;

            x2 = mul(x2, workingKey[keyOff++]);
            x1 += x2;
            x1 &= MASK;

            x1 = mul(x1, workingKey[keyOff++]);
            x2 += x1;
            x2 &= MASK;

            x0 ^= x1;
            x3 ^= x2;
            x1 ^= t1;
            x2 ^= t0;
        }
        writeBigEndianInt16(output, mul(x0, workingKey[keyOff++]));
        writeBigEndianInt16(output, x2 + workingKey[keyOff++]);
        writeBigEndianInt16(output, x1 + workingKey[keyOff++]);
        writeBigEndianInt16(output, mul(x3, workingKey[keyOff]));
    }

    private int mul(int x, int y) {
        if (x == 0) {
            x = (BASE - y);
        } else if (y == 0) {
            x = (BASE - x);
        } else {
            var p = x * y;
            y = p & MASK;
            x = p >>> 16;
            x = y - x + ((y < x) ? 1 : 0);
        }

        return x & MASK;
    }

    private int mulInv(int x) {
        if (x < 2) {
            return x;
        }

        var t0 = 1;
        var t1 = BASE / x;
        var y = BASE % x;
        while (y != 1) {
            var q = x / y;
            x = x % y;
            t0 = (t0 + (t1 * q)) & MASK;
            if (x == 1) {
                return t0;
            }
            q = y / x;
            y = y % x;
            t1 = (t1 + (t0 * q)) & MASK;
        }

        return (1 - t1) & MASK;
    }

    private int addInv(int x) {
        return (-x) & MASK;
    }
}
