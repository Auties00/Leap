package it.auties.leap.tls.ec.implementation;

import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDecoder;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ExplicitPrimeParameters implements TlsECParameters {
    private static final TlsECParametersDecoder DECODER = input -> {
        var prime = readBytesLittleEndian8(input);
        var a = readBytesLittleEndian8(input);
        var b = readBytesLittleEndian8(input);
        var encoding = readBytesLittleEndian8(input);
        var order = readBytesLittleEndian8(input);
        var cofactor = readBytesLittleEndian8(input);
        return new ExplicitPrimeParameters(prime, a, b, encoding, order, cofactor);
    };

    private final byte[] prime;
    private final byte[] a;
    private final byte[] b;
    private final byte[] encoding;
    private final byte[] order;
    private final byte[] cofactor;

    public ExplicitPrimeParameters(byte[] prime, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        this.prime = prime;
        this.a = a;
        this.b = b;
        this.encoding = encoding;
        this.order = order;
        this.cofactor = cofactor;
    }

    public static TlsECParametersDecoder decoder() {
        return DECODER;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian8(buffer, prime);
        writeBytesLittleEndian8(buffer, a);
        writeBytesLittleEndian8(buffer, b);
        writeBytesLittleEndian8(buffer, encoding);
        writeBytesLittleEndian8(buffer, order);
        writeBytesLittleEndian8(buffer, cofactor);
    }

    @Override
    public int length() {
        return INT8_LENGTH + prime.length
                + INT8_LENGTH + a.length
                + INT8_LENGTH + b.length
                + INT8_LENGTH + encoding.length
                + INT8_LENGTH + order.length
                + INT8_LENGTH + cofactor.length;
    }
}
