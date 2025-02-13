package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompressionHandler;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;

public class UnsupportedCompressionHandler implements TlsCompressionHandler {
    private static final UnsupportedCompressionHandler INSTANCE = new UnsupportedCompressionHandler();

    private UnsupportedCompressionHandler() {

    }

    public static UnsupportedCompressionHandler instance() {
        return INSTANCE;
    }

    @Override
    public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
        throw TlsException.stub();
    }
}
