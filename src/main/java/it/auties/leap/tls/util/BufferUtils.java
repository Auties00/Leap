package it.auties.leap.tls.util;

import java.io.InputStream;
import java.nio.ByteBuffer;

public final class BufferUtils {
    public static final int INT8_LENGTH = 1;
    public static final int INT16_LENGTH = 2;
    public static final int INT24_LENGTH = 3;
    public static final int INT32_LENGTH = 4;
    public static final int INT64_LENGTH = 8;

    public static byte readLittleEndianInt8(ByteBuffer m) {
        return m.get();
    }

    public static int readLittleEndianInt16(ByteBuffer m) {
        return (m.get() & 0xFF)
                | ((m.get() & 0xFF) << 8);
    }

    public static int readLittleEndianInt24(ByteBuffer m) {
        return (m.get() & 0xFF)
                | ((m.get() & 0xFF) << 8)
                | ((m.get() & 0xFF) << 16);
    }

    public static int readLittleEndianInt32(ByteBuffer m) {
        return (m.get() & 0xFF)
                | ((m.get() & 0xFF) << 8)
                | ((m.get() & 0xFF) << 16)
                | ((m.get() & 0xFF) << 24);
    }

    public static byte readBigEndianInt8(ByteBuffer input) {
        return input.get();
    }

    public static int readBigEndianInt16(ByteBuffer input) {
        return ((input.get() & 0xff) << 8)
                | (input.get() & 0xff);
    }

    public static int readBigEndianInt16(byte[] bs, int off) {
        return ((bs[off] & 0xff) << 8)
                | (bs[off + 1] & 0xff);
    }

    public static int readBigEndianInt24(ByteBuffer input) {
        return ((input.get() & 0xff) << 16)
                | ((input.get() & 0xff) << 8)
                | (input.get() & 0xff);
    }

    public static int readBigEndianInt24(byte[] bs, int off) {
        return ((bs[off] & 0xff) << 16)
                | ((bs[off + 1] & 0xff) << 8)
                | (bs[off + 2] & 0xff);
    }

    public static int readBigEndianInt32(ByteBuffer input) {
        return (input.get() << 24)
                | ((input.get() & 0xff) << 16)
                | ((input.get() & 0xff) << 8)
                | (input.get() & 0xff);
    }

    public static int readBigEndianInt32(byte[] bs, int off) {
        int n = bs[off] << 24;
        n |= (bs[++off] & 0xff) << 16;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff);
        return n;
    }

    public static long readBigEndianInt64(ByteBuffer input) {
        return ((long) (input.get() & 0xFF) << 56)
                | ((long) (input.get() & 0xFF) << 48)
                | ((long) (input.get() & 0xFF) << 40)
                | ((long) (input.get() & 0xFF) << 32)
                | ((long) (input.get() & 0xFF) << 24)
                | ((long) (input.get() & 0xFF) << 16)
                | ((long) (input.get() & 0xFF) << 8)
                | ((long) (input.get() & 0xFF));
    }

    public static long readBigEndianInt64(byte[] bs, int off) {
        return ((long) (bs[off] & 0xFF) << 56)
                | ((long) (bs[++off] & 0xFF) << 48)
                | ((long) (bs[++off] & 0xFF) << 40)
                | ((long) (bs[++off] & 0xFF) << 32)
                | ((long) (bs[++off] & 0xFF) << 24)
                | ((long) (bs[++off] & 0xFF) << 16)
                | ((long) (bs[++off] & 0xFF) << 8)
                | ((long) (bs[++off] & 0xFF));
    }

    public static void writeLittleEndianInt8(ByteBuffer m, int i) {
        m.put((byte) (i & 0xFF));
    }

    public static void writeLittleEndianInt16(ByteBuffer m, int i) {
        m.put((byte) (i & 0xFF));
        m.put((byte) ((i >> 8) & 0xFF));
    }

    public static void writeLittleEndianInt24(ByteBuffer m, int i) {
        writeLittleEndianInt16(m, i);
        m.put((byte) ((i >> 16) & 0xFF));
    }

    public static void writeLittleEndianInt32(ByteBuffer m, int i) {
        writeLittleEndianInt24(m, i);
        m.put((byte) ((i >> 24) & 0xFF));
    }

    public static void writeLittleEndianInt64(ByteBuffer output, long n) {
        output.put((byte) n);
        output.put((byte) (n >> 8));
        output.put((byte) (n >> 16));
        output.put((byte) (n >> 24));
        output.put((byte) (n >> 32));
        output.put((byte) (n >> 40));
        output.put((byte) (n >> 48));
        output.put((byte) (n >> 56));
    }

    public static void writeBigEndianInt8(ByteBuffer m, int i) {
        m.put((byte) (i & 0xFF));
    }

    public static void writeBigEndianInt16(ByteBuffer output, int n) {
        output.put((byte) (n >>> 8));
        output.put((byte) n);
    }

    public static void writeBigEndianInt24(ByteBuffer output, int n) {
        output.put((byte) (n >>> 16));
        writeBigEndianInt16(output, n);
    }

    public static void writeBigEndianInt24(int n, byte[] bs, int off) {
        bs[off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n);
    }

    public static void writeBigEndianInt32(ByteBuffer output, int n) {
        output.put((byte) (n >>> 24));
        writeBigEndianInt24(output, n);
    }

    public static void writeBigEndianInt32(int n, byte[] bs, int off) {
        bs[off] = (byte) (n >>> 24);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n);
    }

    public static void writeBigEndianInt64(ByteBuffer output, long n) {
        output.put((byte) (n >> 56));
        output.put((byte) (n >> 48));
        output.put((byte) (n >> 40));
        output.put((byte) (n >> 32));
        output.put((byte) (n >> 24));
        output.put((byte) (n >> 16));
        output.put((byte) (n >> 8));
        output.put((byte) n);
    }

    public static ByteBuffer readBuffer(ByteBuffer buffer, int length) {
        var sliced = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return sliced;
    }

    public static ByteBuffer readBufferBigEndian8(ByteBuffer buffer) {
        var length = readBigEndianInt8(buffer);
        return readBuffer(buffer, length);
    }

    public static ByteBuffer readBufferBigEndian16(ByteBuffer buffer) {
        var length = readBigEndianInt16(buffer);
        return readBuffer(buffer, length);
    }

    public static ByteBuffer readBufferBigEndian24(ByteBuffer buffer) {
        var length = readBigEndianInt24(buffer);
        return readBuffer(buffer, length);
    }

    public static ByteBuffer readBufferLittleEndian8(ByteBuffer buffer) {
        var length = readLittleEndianInt8(buffer);
        return readBuffer(buffer, length);
    }

    public static ByteBuffer readBufferLittleEndian16(ByteBuffer buffer) {
        var length = readLittleEndianInt16(buffer);
        return readBuffer(buffer, length);
    }

    public static ByteBuffer readBufferLittleEndian24(ByteBuffer buffer) {
        var length = readLittleEndianInt24(buffer);
        return readBuffer(buffer, length);
    }

    public static byte[] readBytes(ByteBuffer buffer, int length) {
        var bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    public static byte[] readBytesLittleEndian8(ByteBuffer buffer) {
        var length = readLittleEndianInt8(buffer);
        return readBytes(buffer, length);
    }

    public static byte[] readBytesLittleEndian16(ByteBuffer buffer) {
        var length = readLittleEndianInt16(buffer);
        return readBytes(buffer, length);
    }

    public static byte[] readBytesLittleEndian24(ByteBuffer buffer) {
        var length = readLittleEndianInt24(buffer);
        return readBytes(buffer, length);
    }

    public static byte[] readBytesBigEndian8(ByteBuffer buffer) {
        var length = readBigEndianInt8(buffer);
        return readBytes(buffer, length);
    }

    public static byte[] readBytesBigEndian16(ByteBuffer buffer) {
        var length = readBigEndianInt16(buffer);
        return readBytes(buffer, length);
    }

    public static byte[] readBytesBigEndian24(ByteBuffer buffer) {
        var length = readBigEndianInt24(buffer);
        return readBytes(buffer, length);
    }

    public static InputStream readStream(ByteBuffer buffer, int length) {
        var sliced = readBuffer(buffer, length);
        return new ByteBufferBackedInputStream(sliced);
    }

    public static InputStream readStreamLittleEndian8(ByteBuffer buffer) {
        var sliced = readBufferLittleEndian8(buffer);
        return new ByteBufferBackedInputStream(sliced);
    }

    public static InputStream readStreamLittleEndian16(ByteBuffer buffer) {
        var sliced = readBufferLittleEndian16(buffer);
        return new ByteBufferBackedInputStream(sliced);
    }

    public static InputStream readStreamLittleEndian24(ByteBuffer buffer) {
        var sliced = readBufferLittleEndian24(buffer);
        return new ByteBufferBackedInputStream(sliced);
    }

    public static InputStream readStreamBigEndian8(ByteBuffer buffer) {
        var length = readBigEndianInt8(buffer);
        return readStream(buffer, length);
    }

    public static InputStream readStreamBigEndian16(ByteBuffer buffer) {
        var length = readBigEndianInt16(buffer);
        return readStream(buffer, length);
    }

    public static InputStream readStreamBigEndian24(ByteBuffer buffer) {
        var length = readBigEndianInt24(buffer);
        return readStream(buffer, length);
    }

    public static void writeBytes(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        m.put(s);
    }

    public static void writeBytesLittleEndian8(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeLittleEndianInt8(m, 0);
            return;
        }

        writeLittleEndianInt8(m, s.length);
        m.put(s);
    }

    public static void writeBytesLittleEndian16(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeLittleEndianInt16(m, 0);
            return;
        }

        writeLittleEndianInt16(m, s.length);
        m.put(s);
    }

    public static void writeBytesLittleEndian24(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeLittleEndianInt24(m, 0);
            return;
        }

        writeLittleEndianInt24(m, s.length);
        m.put(s);
    }

    public static void writeBytesBigEndian8(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeBigEndianInt8(m, 0);
            return;
        }

        writeBigEndianInt8(m, s.length);
        m.put(s);
    }

    public static void writeBytesBigEndian16(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeBigEndianInt16(m, 0);
            return;
        }

        writeBigEndianInt16(m, s.length);
        m.put(s);
    }

    public static void writeBytesBigEndian24(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeBigEndianInt24(m, 0);
            return;
        }

        writeBigEndianInt24(m, s.length);
        m.put(s);
    }

    public static void writeBuffer(ByteBuffer m, ByteBuffer s) {
        if(s == null) {
            return;
        }

        m.put(s);
    }

    public static void writeBufferLittleEndian8(ByteBuffer m, ByteBuffer s) {
        if(s == null) {
            return;
        }

        if (!s.hasRemaining()) {
            writeLittleEndianInt8(m, 0);
            return;
        }

        writeLittleEndianInt8(m, s.remaining());
        m.put(s);
    }

    public static void writeBufferLittleEndian16(ByteBuffer m, ByteBuffer s) {
        if(s == null) {
            return;
        }

        if (!s.hasRemaining()) {
            writeLittleEndianInt16(m, 0);
            return;
        }

        writeLittleEndianInt16(m, s.remaining());
        m.put(s);
    }

    public static void writeBufferLittleEndian24(ByteBuffer m, ByteBuffer s) {
        if(s == null) {
            return;
        }

        if (!s.hasRemaining()) {
            writeLittleEndianInt24(m, 0);
            return;
        }

        writeLittleEndianInt24(m, s.remaining());
        m.put(s);
    }

    public static void assertBytesBigEndian8(byte[] input) {
        if (input.length <= 255) {
            return;
        }

        throw new InternalError("Invalid payload length");
    }

    public static void assertEmpty(ByteBuffer m) {
        assertLength(m, 0);
    }

    public static void assertLength(ByteBuffer m, int expectedLength) {
        if (m.remaining() == expectedLength) {
            return;
        }

        throw new InternalError("Unexpected payload length, remaining: " + (m.remaining() - expectedLength));
    }

    public static ScopedWrite scopedWrite(ByteBuffer buffer, int messageLength, boolean readable) {
        if(readable) {
            var oldPosition = buffer.position();
            var expectedPosition = oldPosition + messageLength;
            buffer.limit(expectedPosition);
            return new ScopedWrite(buffer, expectedPosition, oldPosition);
        }else {
            var oldLimit = buffer.limit();
            var expectedPosition = buffer.position() + messageLength;
            buffer.limit(expectedPosition);
            return new ScopedWrite(buffer, oldLimit, -1);
        }
    }

    public static ScopedRead scopedRead(ByteBuffer buffer, int messageLength) {
        var oldLimit = buffer.limit();
        buffer.limit(buffer.position() + messageLength);
        return new ScopedRead(buffer, oldLimit);
    }

    public static void assertNotEquals(ByteBuffer first, ByteBuffer second) {
        if(equals(first, second)) {
            throw new UnsupportedOperationException("The message buffer cannot be the same as the output buffer");
        }
    }

    public static boolean equals(ByteBuffer first, ByteBuffer second) {
        return first == second
                || (!first.isDirect() && !second.isDirect() && first.array() == second.array());
    }

    public static long bigEndianToLong(byte[] bs, int off) {
        int hi = readBigEndianInt32(bs, off);
        int lo = readBigEndianInt32(bs, off + 4);
        return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
    }

    public static void bigEndianToLong(byte[] bs, int bsOff, long[] ns, int nsOff, int nsLen) {
        for (int i = 0; i < nsLen; ++i) {
            ns[nsOff + i] = bigEndianToLong(bs, bsOff);
            bsOff += 8;
        }
    }

    public static void writeBigEndianInt64(long n, byte[] bs, int off) {
        writeBigEndianInt32((int) (n >>> 32), bs, off);
        writeBigEndianInt32((int) (n & 0xffffffffL), bs, off + 4);
    }

    public static void writeBigEndianInt64(long[] ns, int nsOff, int nsLen, byte[] bs, int bsOff) {
        for (int i = 0; i < nsLen; ++i) {
            writeBigEndianInt64(ns[nsOff + i], bs, bsOff);
            bsOff += 8;
        }
    }

    public static int readLittleEndianInt32(byte[] bs, int off) {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    public static void readLittleEndianInt32(byte[] bs, int bOff, int[] ns, int nOff, int count) {
        for (int i = 0; i < count; ++i) {
            ns[nOff + i] = readLittleEndianInt32(bs, bOff);
            bOff += 4;
        }
    }

    public static int[] readLittleEndianInt32(byte[] bs, int off, int count) {
        int[] ns = new int[count];
        for (int i = 0; i < ns.length; ++i) {
            ns[i] = readLittleEndianInt32(bs, off);
            off += 4;
        }
        return ns;
    }

    public static byte[] writeLittleEndianInt16(short n) {
        byte[] bs = new byte[2];
        writeLittleEndianInt16(n, bs, 0);
        return bs;
    }

    public static void writeLittleEndianInt16(short n, byte[] bs, int off) {
        bs[off] = (byte) (n);
        bs[++off] = (byte) (n >>> 8);
    }

    public static void writeLittleEndianInt32(int n, byte[] bs, int off) {
        bs[off] = (byte) (n);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 24);
    }

    public static void writeLittleEndianInt64(long n, byte[] bs, int off) {
        bs[off] = ((byte) (n >> 56));
        bs[++off] = ((byte) (n >> 48));
        bs[++off] = ((byte) (n >> 40));
        bs[++off] = ((byte) (n >> 32));
        bs[++off] = ((byte) (n >> 24));
        bs[++off] = ((byte) (n >> 16));
        bs[++off] = ((byte) (n >> 8));
        bs[++off] = ((byte) n);
    }


    public record ScopedWrite(ByteBuffer buffer, int limit, int position) implements AutoCloseable {
        @Override
        public void close() {
            if(buffer.hasRemaining()) {
                throw new InternalError("Invalid payload length");
            }

            buffer.limit(limit);
            if(position != -1) {
                buffer.position(position);
            }
        }
    }

    public record ScopedRead(ByteBuffer buffer, int oldLimit) implements AutoCloseable {
        @Override
        public void close() {
            assertEmpty(buffer);
            buffer.limit(oldLimit);
        }
    }

    private static final class ByteBufferBackedInputStream extends InputStream {
        private final ByteBuffer buf;
        public ByteBufferBackedInputStream(ByteBuffer buf) {
            this.buf = buf;
        }

        public int read() {
            if (!buf.hasRemaining()) {
                return -1;
            }
            return buf.get() & 0xFF;
        }

        public int read(byte[] bytes, int off, int len) {
            if (!buf.hasRemaining()) {
                return -1;
            }

            len = Math.min(len, buf.remaining());
            buf.get(bytes, off, len);
            return len;
        }

        @Override
        public int available() {
            return buf.remaining();
        }
    }
}
