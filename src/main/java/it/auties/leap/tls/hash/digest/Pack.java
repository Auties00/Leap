package it.auties.leap.tls.hash.digest;

import java.nio.ByteBuffer;

final class Pack {
    static int bigEndianToInt(byte[] bs, int off) {
        var n = bs[off] << 24;
        n |= (bs[++off] & 0xff) << 16;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff);
        return n;
    }

    static int bigEndianToInt(ByteBuffer bs, int off) {
        var n = bs.get(off) << 24;
        n |= (bs.get(++off) & 0xff) << 16;
        n |= (bs.get(++off) & 0xff) << 8;
        n |= (bs.get(++off) & 0xff);
        return n;
    }

    static void intToBigEndian(int[] n, byte[] bs, int offset, int length) {
        for (int i : n) {
            if(length < 0) {
                break;
            }

            intToBigEndian(i, bs, offset, length);
            offset += 4;
            length -= 4;
        }
    }

    static void intToBigEndian(int n, byte[] bs, int off, int length) {
        if(length > 0) {
            bs[off] = (byte) (n >>> 24);
        }

        if(length > 1) {
            bs[++off] = (byte) (n >>> 16);
        }

        if(length > 2) {
            bs[++off] = (byte) (n >>> 8);
        }

        if(length > 3) {
            bs[++off] = (byte) (n);
        }
    }

    static int littleEndianToInt(byte[] bs, int off) {
        var n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    static int littleEndianToInt(ByteBuffer bs, int off) {
        var n = bs.get(off) & 0xff;
        n |= (bs.get(++off) & 0xff) << 8;
        n |= (bs.get(++off) & 0xff) << 16;
        n |= bs.get(++off) << 24;
        return n;
    }

    static void intToLittleEndian(int n, byte[] bs, int off, int length) {
        if(length > 0) {
            bs[off] = (byte) (n);
        }

        if(length > 1) {
            bs[++off] = (byte) (n >>> 8);
        }

        if(length > 2) {
            bs[++off] = (byte) (n >>> 16);
        }

        if(length > 3) {
            bs[++off] = (byte) (n >>> 24);
        }
    }

    static void longToBigEndian(long n, byte[] bs, int off, int length) {
        intToBigEndian((int) (n >>> 32), bs, off, length);
        intToBigEndian((int) (n & 0xffffffffL), bs, off + 4, length - 4);
    }

    static long bigEndianToLong(byte[] bs, int off) {
        var hi = bigEndianToInt(bs, off);
        var lo = bigEndianToInt(bs, off + 4);
        return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
    }

    static long bigEndianToLong(ByteBuffer bs, int off) {
        var hi = bigEndianToInt(bs, off);
        var lo = bigEndianToInt(bs, off + 4);
        return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
    }
}
