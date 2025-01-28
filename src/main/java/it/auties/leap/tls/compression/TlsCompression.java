package it.auties.leap.tls.compression;

import it.auties.leap.tls.exception.TlsException;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public sealed interface TlsCompression extends TlsCompressionHandler {
    static TlsCompression none() {
        return None.INSTANCE;
    }

    static TlsCompression deflate() {
        return Deflate.INSTANCE;
    }

    static TlsCompression reservedForPrivateUse(byte id, TlsCompressionHandler consumer) {
        return new Reserved(id, consumer);
    }

    static List<TlsCompression> allCompressions() {
        return List.of(None.INSTANCE, Deflate.INSTANCE);
    }

    byte id();

    final class None implements TlsCompression {
        private static final None INSTANCE = new None();

        @Override
        public byte id() {
            return 0;
        }

        @Override
        public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
            output.put(input);
        }
    }

    final class Deflate implements TlsCompression {
        private static final Deflate INSTANCE = new Deflate();

        @Override
        public byte id() {
            return 1;
        }

        @Override
        public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
            try {
                if (forCompression) {
                    var deflater = new Deflater();
                    deflater.setInput(input);
                    deflater.finish();
                    var compressedDataLength = deflater.deflate(output);
                    deflater.end();
                    output.limit(output.position() + compressedDataLength);
                } else {
                    var inflater = new Inflater();
                    inflater.setInput(input);
                    var compressedDataLength = inflater.inflate(output);
                    inflater.end();
                    output.limit(output.position() + compressedDataLength);
                }
            } catch (DataFormatException exception) {
                throw new TlsException("Cannot process data", exception);
            }
        }
    }

    non-sealed class Reserved implements TlsCompression {
        private final byte id;
        private final TlsCompressionHandler delegate;

        protected Reserved(byte id, TlsCompressionHandler delegate) {
            if (id < -32 || id > -1) {
                throw new TlsException(
                        "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                        URI.create("https://www.ietf.org/rfc/rfc3749.txt"),
                        "2"
                );
            }

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
