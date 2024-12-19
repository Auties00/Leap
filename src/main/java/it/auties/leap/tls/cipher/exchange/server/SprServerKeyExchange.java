package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.INT16_LENGTH;
import static it.auties.leap.tls.BufferHelper.writeBytesLittleEndian16;

public final class SprServerKeyExchange extends TlsKeyExchange.Server {
    private final byte[] n;
    private final byte[] g;
    private final byte[] s;
    private final byte[] b;

    public SprServerKeyExchange(byte[] n, byte[] g, byte[] s, byte[] b) {
        this.n = n;
        this.g = g;
        this.s = s;
        this.b = b;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, n);
        writeBytesLittleEndian16(buffer, g);
        writeBytesLittleEndian16(buffer, s);
        writeBytesLittleEndian16(buffer, b);
    }

    @Override
    public int length() {
        return INT16_LENGTH + n.length
                + INT16_LENGTH + g.length
                + INT16_LENGTH + s.length
                + INT16_LENGTH + b.length;
    }
}
