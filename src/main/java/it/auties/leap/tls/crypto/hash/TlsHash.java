package it.auties.leap.tls.crypto.hash;

import it.auties.leap.tls.TlsHashType;

import java.nio.ByteBuffer;

public sealed abstract class TlsHash permits GOSTR256Digest, MD5Digest, NULLDigest, SHA1Digest, SHA256Digest, SHA384Digest, SM3Digest {
    public static TlsHash of(TlsHashType hashType) {
        return switch (hashType) {
            case NULL -> NULLDigest.INSTANCE;
            case GOSTR341112_256 -> new GOSTR256Digest();
            case MD5 -> new MD5Digest();
            case SHA1 -> new SHA1Digest();
            case SHA256 -> new SHA256Digest();
            case SHA384 -> new SHA384Digest();
            case SM3 -> new SM3Digest();
        };
    }

    public abstract void update(byte input);

    public abstract void update(ByteBuffer input);

    public abstract void update(byte[] input, int offset, int len);

    public abstract int digest(byte[] output, int offset, int length, boolean reset);

    public abstract void reset();

    public abstract TlsHashType type();

    public void update(byte[] input) {
        update(input, 0, input.length);
    }

    public byte[] digest(boolean reset) {
        var length = type().length();
        var result = new byte[length];
        digest(result, 0, length, reset);
        return result;
    }

    public int digest(byte[] output, int offset, boolean reset) {
        return digest(output, offset, type().length(), reset);
    }

    public int digest(byte[] output, boolean reset) {
        return digest(output, 0, type().length(), reset);
    }

    public byte[] digest(boolean reset, int offset, int length) {
        var result = new byte[length];
        digest(result, offset, length, reset);
        return result;
    }

    protected int bigEndianToInt(byte[] bs, int off) {
        var n = bs[off] << 24;
        n |= (bs[++off] & 0xff) << 16;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff);
        return n;
    }

    protected int bigEndianToInt(ByteBuffer bs, int off) {
        var n = bs.get(off) << 24;
        n |= (bs.get(++off) & 0xff) << 16;
        n |= (bs.get(++off) & 0xff) << 8;
        n |= (bs.get(++off) & 0xff);
        return n;
    }

    protected void intToBigEndian(int[] n, byte[] bs, int offset, int length) {
        for (int i : n) {
            if(length < 0) {
                break;
            }

            intToBigEndian(i, bs, offset, length);
            offset += 4;
            length -= 4;
        }
    }

    protected void intToBigEndian(int n, byte[] bs, int off, int length) {
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

    protected int readLittleEndianInt32(byte[] bs, int off) {
        var n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    protected int readLittleEndianInt32(ByteBuffer bs, int off) {
        var n = bs.get(off) & 0xff;
        n |= (bs.get(++off) & 0xff) << 8;
        n |= (bs.get(++off) & 0xff) << 16;
        n |= bs.get(++off) << 24;
        return n;
    }

    protected void writeLittleEndianInt32(int n, byte[] bs, int off, int length) {
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

    protected void longToBigEndian(long n, byte[] bs, int off, int length) {
        intToBigEndian((int) (n >>> 32), bs, off, length);
        intToBigEndian((int) (n & 0xffffffffL), bs, off + 4, length - 4);
    }

    protected long bigEndianToLong(byte[] bs, int off) {
        var hi = bigEndianToInt(bs, off);
        var lo = bigEndianToInt(bs, off + 4);
        return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
    }

    protected long bigEndianToLong(ByteBuffer bs, int off) {
        var hi = bigEndianToInt(bs, off);
        var lo = bigEndianToInt(bs, off + 4);
        return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
    }
}
