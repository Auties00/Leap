package it.auties.leap.tls;

import java.net.URI;
import java.nio.ByteBuffer;

public sealed abstract class TlsCompression implements TlsCompressionHandler {
    public abstract byte id();

    public static TlsCompression none() {
        return None.INSTANCE;
    }

    public static TlsCompression deflate() {
        return Deflate.INSTANCE;
    }

    public static TlsCompression reserved(byte id, TlsCompressionHandler consumer) {
        var unsignedId = Byte.toUnsignedInt(id);
        if(unsignedId <= 63) {
            throw new TlsSpecificationException(
                    "Values from 0 (zero) through 63 decimal (0x3F) inclusive are reserved for IETF Standards Track protocols.",
                    URI.create("https://www.ietf.org/rfc/rfc3749.txt"),
                    "2"
            );
        }else if(unsignedId <= 223) {
            throw new TlsSpecificationException(
                    "Values from 64 decimal (0x40) through 223 decimal (0xDF) inclusive are reserved for assignment for non-Standards Track methods.",
                    URI.create("https://www.ietf.org/rfc/rfc3749.txt"),
                    "2"
            );
        }else {
            return new Reserved(id, consumer);
        }
    }

    private static final class None extends TlsCompression {
        private static final None INSTANCE = new None();

        @Override
        public byte id() {
            return 0;
        }

        @Override
        public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {

        }
    }

    private static final class Deflate extends TlsCompression {
        private static final Deflate INSTANCE = new Deflate();

        @Override
        public byte id() {
            return 1;
        }

        @Override
        public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {

        }
    }

    private static final class Reserved extends TlsCompression {
        private final byte id;
        private final TlsCompressionHandler delegate;
        private Reserved(byte id, TlsCompressionHandler delegate) {
            this.id = id;
            this.delegate = delegate;
        }

        @Override
        public byte id() {
            return id;
        }

        @Override
        public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
            delegate.accept(input, output, forCompression);
        }
    }
}
