package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class DeflateCompression implements TlsCompression {
    private static final DeflateCompression INSTANCE = new DeflateCompression();

    private DeflateCompression() {

    }

    public static DeflateCompression instance() {
        return INSTANCE;
    }

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
