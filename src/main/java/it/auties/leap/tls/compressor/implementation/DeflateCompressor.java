package it.auties.leap.tls.compressor.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.compressor.TlsCompressor;

import java.nio.ByteBuffer;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class DeflateCompressor implements TlsCompressor {
    private static final DeflateCompressor INSTANCE = new DeflateCompressor();

    private DeflateCompressor() {

    }

    public static DeflateCompressor instance() {
        return INSTANCE;
    }

    @Override
    public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
        if (forCompression) {
            try(var deflater = new Deflater()) {
                deflater.setInput(input);
                deflater.finish();
                var compressedDataLength = deflater.deflate(output);
                deflater.end();
                output.limit(output.position() + compressedDataLength);
            }
        } else {
            try(var inflater = new Inflater()) {
                inflater.setInput(input);
                var compressedDataLength = inflater.inflate(output);
                inflater.end();
                output.limit(output.position() + compressedDataLength);
            } catch (DataFormatException exception) {
                throw new TlsAlert("Cannot process data", exception);
            }
        }
    }
}
