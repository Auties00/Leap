package it.auties.leap.tls.compression.implementation;

import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.compression.TlsCompressionHandler;
import it.auties.leap.tls.alert.TlsAlert;

import java.net.URI;
import java.nio.ByteBuffer;

public final class ReservedCompression implements TlsCompression {
    private final byte id;
    private final TlsCompressionHandler delegate;

    public ReservedCompression(byte id, TlsCompressionHandler delegate) {
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
    public void accept(ByteBuffer input, ByteBuffer output, boolean forCompression) {
        if(delegate == null) {
            throw TlsAlert.stub();
        }else {
            delegate.accept(input, output, forCompression);
        }
    }
}
