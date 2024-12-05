package it.auties.leap.tls;

import java.io.InputStream;
import java.nio.ByteBuffer;

public final class TlsRecord {
    public static final int INT8_LENGTH = 1;
    public static final int INT16_LENGTH = 2;
    public static final int INT24_LENGTH = 3;

    public static final int MAC_LENGTH = 48;
    public static final int DATA_LENGTH = 16384;
    public static final int PADDING_LENGTH = 256;
    public static final int IV_LENGTH = 16;
    public static final int FRAGMENT_LENGTH = 18432;
    public static final int TLS_HEADER_LENGTH = 5;
    public static final int HANDSHAKE_HEADER_LENGTH = 4;
    public static final int PLAINTEXT_LENGTH = TLS_HEADER_LENGTH
            + IV_LENGTH
            + MAC_LENGTH
            + PADDING_LENGTH;
    public static final int RECORD_LENGTH = TLS_HEADER_LENGTH
            + IV_LENGTH
            + DATA_LENGTH
            + PADDING_LENGTH
            + MAC_LENGTH;
    public static final int LARGE_RECORD_LENGTH = RECORD_LENGTH + DATA_LENGTH;
    public static final int MIN_HASH_LENGTH = 12;

    public static byte readInt8(ByteBuffer m) {
        return m.get();
    }

    public static int readInt16(ByteBuffer m) {
        return ((m.get() & 0xFF) << 8) |
                (m.get() & 0xFF);
    }

    public static int readInt24(ByteBuffer m) {
        return ((m.get() & 0xFF) << 16) |
                ((m.get() & 0xFF) << 8) |
                (m.get() & 0xFF);
    }

    public static int readInt32(ByteBuffer m) {
        return ((m.get() & 0xFF) << 24) |
                ((m.get() & 0xFF) << 16) |
                ((m.get() & 0xFF) << 8) |
                (m.get() & 0xFF);
    }

    public static ByteBuffer readBuffer(ByteBuffer buffer, int length) {
        var sliced = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return sliced;
    }

    public static ByteBuffer readBuffer8(ByteBuffer buffer) {
        var length = readInt8(buffer);
        var sliced = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return sliced;
    }

    public static ByteBuffer readBuffer16(ByteBuffer buffer) {
        var length = readInt16(buffer);
        var sliced = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return sliced;
    }

    public static ByteBuffer readBuffer24(ByteBuffer buffer) {
        var length = readInt24(buffer);
        var sliced = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return sliced;
    }

    public static byte[] readBytes(ByteBuffer buffer, int length) {
        var bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    public static byte[] readBytes8(ByteBuffer buffer) {
        var length = readInt8(buffer);
        var bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    public static byte[] readBytes16(ByteBuffer buffer) {
        var length = readInt16(buffer);
        var bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    public static byte[] readBytes24(ByteBuffer buffer) {
        var length = readInt24(buffer);
        var bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    public static InputStream readStream(ByteBuffer buffer, int length) {
        var sliced = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return new ByteBufferBackedInputStream(sliced);
    }

    public static InputStream readStream8(ByteBuffer buffer) {
        var length = readInt8(buffer);
        var sliced = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return new ByteBufferBackedInputStream(sliced);
    }

    public static InputStream readStream16(ByteBuffer buffer) {
        var length = readInt16(buffer);
        var sliced = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return new ByteBufferBackedInputStream(sliced);
    }

    public static InputStream readStream24(ByteBuffer buffer) {
        var length = readInt24(buffer);
        var sliced = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return new ByteBufferBackedInputStream(sliced);
    }

    public static void writeInt8(ByteBuffer m, int i) {
        m.put((byte) (i & 0xFF));
    }

    public static void writeInt8(ByteBuffer m, int i, int count) {
        for(var j = 0; j < count; j++) {
            m.put((byte) (i & 0xFF));
        }
    }

    public static void writeInt16(ByteBuffer m, int i) {
        m.put((byte) ((i >> 8) & 0xFF));
        m.put((byte) (i & 0xFF));
    }

    public static void writeInt24(ByteBuffer m, int i) {
        m.put((byte) ((i >> 16) & 0xFF));
        m.put((byte) ((i >> 8) & 0xFF));
        m.put((byte) (i & 0xFF));
    }

    public static void writeInt32(ByteBuffer m, int i) {
        m.put((byte) ((i >> 24) & 0xFF));
        m.put((byte) ((i >> 16) & 0xFF));
        m.put((byte) ((i >> 8) & 0xFF));
        m.put((byte) (i & 0xFF));
    }

    public static void writeBytes(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        m.put(s);
    }

    public static void writeBytesVarInt(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeInt8(m, 0);
            return;
        }



        writeInt8(m, s.length);
        m.put(s);
    }

    public static void writeBytes8(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeInt8(m, 0);
            return;
        }

        writeInt8(m, s.length);
        m.put(s);
    }

    public static void writeBytes16(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeInt16(m, 0);
            return;
        }

        writeInt16(m, s.length);
        m.put(s);
    }

    public static void writeBytes24(ByteBuffer m, byte[] s) {
        if(s == null) {
            return;
        }

        if (s.length == 0) {
            writeInt24(m, 0);
            return;
        }

        writeInt24(m, s.length);
        m.put(s);
    }

    public static void writeBuffer(ByteBuffer m, ByteBuffer s) {
        if(s == null) {
            return;
        }

        m.put(s);
    }

    public static void writeBuffer8(ByteBuffer m, ByteBuffer s) {
        if(s == null) {
            return;
        }

        if (!s.hasRemaining()) {
            writeInt8(m, 0);
            return;
        }

        writeInt8(m, s.remaining());
        m.put(s);
    }

    public static void writeBuffer16(ByteBuffer m, ByteBuffer s) {
        if(s == null) {
            return;
        }

        if (!s.hasRemaining()) {
            writeInt16(m, 0);
            return;
        }

        writeInt16(m, s.remaining());
        m.put(s);
    }

    public static void writeBuffer24(ByteBuffer m, ByteBuffer s) {
        if(s == null) {
            return;
        }

        if (!s.hasRemaining()) {
            writeInt24(m, 0);
            return;
        }

        writeInt24(m, s.remaining());
        m.put(s);
    }

    public static void assertEmpty(ByteBuffer m) {
        assertLength(m, 0);
    }

    public static void assertLength(ByteBuffer m, int expectedLength) {
        if (m.remaining() == expectedLength) {
            return;
        }

        throw new InternalError("Invalid payload length");
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
        if(first == second || (!first.isDirect() && !first.isDirect() && first.array() == second.array())) {
            throw new UnsupportedOperationException("The message buffer cannot be the same as the output buffer");
        }
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
    }
}
