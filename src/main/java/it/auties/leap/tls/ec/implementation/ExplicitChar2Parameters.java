package it.auties.leap.tls.ec.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.group.TlsSupportedCurve;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ExplicitChar2Parameters implements TlsECParameters {
    private static final byte BASIS_TRINOMIAL = 1;
    private static final byte BASIS_PENTANOMIAL = 2;

    private static final TlsECParametersDeserializer DESERIALIZER = new TlsECParametersDeserializer() {
        @Override
        public byte type() {
            return 2;
        }

        @Override
        public TlsECParameters deserialize(ByteBuffer input) {
            var m = readBigEndianInt16(input);
            var basis = readBigEndianInt8(input);
            return switch (basis) {
                case BASIS_TRINOMIAL -> {
                    var k = new BigInteger(1, readBytesBigEndian8(input))
                            .intValueExact();
                    var a = readBytesBigEndian8(input);
                    var b = readBytesBigEndian8(input);
                    var encoding = readBytesBigEndian8(input);
                    var order = readBytesBigEndian8(input);
                    var cofactor = readBytesBigEndian8(input);
                    yield new ExplicitChar2Parameters(m, basis, k, a, b, encoding, order, cofactor);
                }
                case BASIS_PENTANOMIAL -> {
                    var k1 = new BigInteger(1, readBytesBigEndian8(input))
                            .intValueExact();
                    var k2 = new BigInteger(1, readBytesBigEndian8(input))
                            .intValueExact();
                    var k3 = new BigInteger(1, readBytesBigEndian8(input))
                            .intValueExact();
                    var a = readBytesBigEndian8(input);
                    var b = readBytesBigEndian8(input);
                    var encoding = readBytesBigEndian8(input);
                    var order = readBytesBigEndian8(input);
                    var cofactor = readBytesBigEndian8(input);
                    yield new ExplicitChar2Parameters(m, basis, k1, k2, k3, a, b, encoding, order, cofactor);
                }
                default -> throw new TlsException("Unknown basis: " + basis);
            };
        }
    };

    private final int m;
    private final byte basis;
    private final int k1;
    private final int k2;
    private final int k3;
    private final byte[] a;
    private final byte[] b;
    private final byte[] encoding;
    private final byte[] order;
    private final byte[] cofactor;

    public ExplicitChar2Parameters(int m, byte basis, int k, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        this(m, basis, k, 0, 0, a, b, encoding, order, cofactor);
    }

    public ExplicitChar2Parameters(int m, byte basis, int k1, int k2, int k3, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        this.m = m;
        this.basis = basis;
        this.k1 = k1;
        this.k2 = k2;
        this.k3 = k3;
        this.a = a;
        this.b = b;
        this.encoding = encoding;
        this.order = order;
        this.cofactor = cofactor;
    }

    public static TlsECParametersDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, m);
        writeBigEndianInt8(buffer, basis);
        switch (basis) {
            case BASIS_TRINOMIAL -> writeBigEndianInt8(buffer, k1);
            case BASIS_PENTANOMIAL -> {
                writeBigEndianInt8(buffer, k1);
                writeBigEndianInt8(buffer, k2);
                writeBigEndianInt8(buffer, k3);
            }
            default -> throw new TlsException("Unknown basis: " + basis);
        }
        writeBytesBigEndian8(buffer, a);
        writeBytesBigEndian8(buffer, b);
        writeBytesBigEndian8(buffer, encoding);
        writeBytesBigEndian8(buffer, order);
        writeBytesBigEndian8(buffer, cofactor);
    }

    @Override
    public int length() {
        return INT16_LENGTH
                + INT8_LENGTH
                + kLength()
                + INT8_LENGTH + a.length
                + INT8_LENGTH + b.length
                + INT8_LENGTH + encoding.length
                + INT8_LENGTH + order.length
                + INT8_LENGTH + cofactor.length;
    }

    private int kLength() {
        return switch (basis) {
            case BASIS_TRINOMIAL -> INT8_LENGTH;
            case BASIS_PENTANOMIAL -> INT8_LENGTH + INT8_LENGTH + INT8_LENGTH;
            default -> throw new TlsException("Unknown basis: " + basis);
        };
    }

    @Override
    public TlsSupportedCurve toGroup(TlsContext context) {
        return TlsSupportedCurve.explicitChar2(this);
    }
}
