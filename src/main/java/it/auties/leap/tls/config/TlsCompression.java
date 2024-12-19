package it.auties.leap.tls.config;

import it.auties.leap.tls.exception.TlsException;

import java.net.URI;
import java.nio.ByteBuffer;

public sealed interface TlsCompression {
    static TlsCompression none() {
        return None.INSTANCE;
    }

    static TlsCompression deflate() {
        return Deflate.INSTANCE;
    }

    static TlsCompression reservedForPrivateUse(byte id, Reserved.Handler consumer) {
        if(id < -32 || id > -1) {
            throw new TlsException(
                    "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                    URI.create("https://www.ietf.org/rfc/rfc3749.txt"),
                    "2"
            );
        }

        return new Reserved(id, consumer);
    }

    byte id();
    boolean accept(ByteBuffer input, ByteBuffer output, boolean forCompression);

    final class None implements TlsCompression {
        private static final None INSTANCE = new None();

        @Override
        public byte id() {
            return 0;
        }

        @Override
        public boolean accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
            return false;
        }
    }

    final class Deflate implements TlsCompression {
        private static final Deflate INSTANCE = new Deflate();

        @Override
        public byte id() {
            return 1;
        }

        @Override
        public boolean accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
            return false;
        }
    }

    final class Reserved implements TlsCompression {
        private final byte id;
        private final Handler delegate;
        private Reserved(byte id, Handler delegate) {
            this.id = id;
            this.delegate = delegate;
        }

        @Override
        public byte id() {
            return id;
        }

        @Override
        public boolean accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
            return delegate.accept(input, output, forCompression);
        }

        @FunctionalInterface
        public interface Handler {
            boolean accept(ByteBuffer input, ByteBuffer output, boolean forCompression);

            static Handler unsupported() {
                return Unsupported.INSTANCE;
            }
        }

        private static final class Unsupported implements Handler {
            private static final Handler INSTANCE = new Unsupported();

            private Unsupported() {

            }

            @Override
            public boolean accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
                return false;
            }
        }
    }
}
