package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.compressor.TlsCompressor;

import java.net.URI;

public final class ReservedCompression implements TlsCompression {
    private final byte id;
    private final TlsCompressor delegate;

    public ReservedCompression(byte id, TlsCompressor delegate) {
        if (id < -32 || id > -1) {
            throw new TlsAlert(
                    "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                    URI.create("https://www.ietf.org/rfc/rfc3749.txt"),
                    "2"
            );
        }

        this.id = id;
        this.delegate = delegate;
    }

    @Override
    public Byte id() {
        return id;
    }

    @Override
    public TlsCompressor compressor() {
        if(delegate == null) {
            throw TlsAlert.stub();
        }

        return delegate;
    }
}
