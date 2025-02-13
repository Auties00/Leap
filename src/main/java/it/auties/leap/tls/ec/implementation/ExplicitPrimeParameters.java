package it.auties.leap.tls.ec.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ExplicitPrimeParameters implements TlsECParameters {
    private static final TlsECParametersDeserializer DESERIALIZER = new TlsECParametersDeserializer() {
        @Override
        public byte type() {
            return 1;
        }

        @Override
        public TlsECParameters deserialize(ByteBuffer input) {
            var prime = readBytesBigEndian8(input);
            var a = readBytesBigEndian8(input);
            var b = readBytesBigEndian8(input);
            var encoding = readBytesBigEndian8(input);
            var order = readBytesBigEndian8(input);
            var cofactor = readBytesBigEndian8(input);
            return new ExplicitPrimeParameters(prime, a, b, encoding, order, cofactor);
        }
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

    public static TlsECParametersDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian8(buffer, prime);
        writeBytesBigEndian8(buffer, a);
        writeBytesBigEndian8(buffer, b);
        writeBytesBigEndian8(buffer, encoding);
        writeBytesBigEndian8(buffer, order);
        writeBytesBigEndian8(buffer, cofactor);
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

    @Override
    public TlsSupportedGroup toGroup(TlsContext context) {
        return TlsSupportedGroup.explicitPrime(this);
    }
}
