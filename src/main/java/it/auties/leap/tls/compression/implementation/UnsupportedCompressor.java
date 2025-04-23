package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.compression.TlsCompressor;

import java.nio.ByteBuffer;

public final class UnsupportedCompressor implements TlsCompressor {
    private static final UnsupportedCompressor INSTANCE = new UnsupportedCompressor();

    private UnsupportedCompressor() {

    }

    public static TlsCompressor instance() {
        return INSTANCE;
    }

    @Override
    public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
        throw new TlsAlert("Unsupported compressor should not be selected", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
    }
}
