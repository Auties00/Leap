package it.auties.leap.tls.ec;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.function.Function;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsEcCurveType extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty {
    static TlsEcCurveType explicitChar2(int m, byte basis, int k, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        return new ExplicitChar2(m, basis, k, a, b, encoding, order, cofactor);
    }

    static TlsEcCurveType explicitChar2(int m, byte basis, int k1, int k2, int k3, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        return new ExplicitChar2(m, basis, k1, k2, k3, a, b, encoding, order, cofactor);
    }

    static TlsEcCurveType explicitPrime(byte[] prime, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        return new ExplicitPrime(prime, a, b, encoding, order, cofactor);
    }

    static TlsEcCurveType namedCurve(int id) {
        return new NamedCurve(id);
    }

    static TlsEcCurveType reservedForPrivateUse(byte id) {
        if (id < -8 || id > -1) {
            throw new TlsAlert(
                    "Only values from 248-255 (decimal) inclusive are reserved for Private Use",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.INTERNAL_ERROR
            );
        }

        return new Reserved(id, null, null, null);
    }

    static TlsEcCurveType reservedForPrivateUse(byte id, TlsEcParametersDeserializer deserializer, TlsSerializableProperty payload, Function<TlsContext, TlsSupportedEllipticCurve> converter) {
        if (id < -8 || id > -1) {
            throw new TlsAlert(
                    "Only values from 248-255 (decimal) inclusive are reserved for Private Use",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.INTERNAL_ERROR
            );
        }

        if(deserializer == null) {
            throw new TlsAlert(
                    "deserializer is null (use TlsEcCurveType.reservedForPrivateUse(id) if the curve should only be advertisable)",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.INTERNAL_ERROR
            );
        }

        if(converter == null) {
            throw new TlsAlert(
                    "converter is null (use TlsEcCurveType.reservedForPrivateUse(id) if the curve should only be advertisable)",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.INTERNAL_ERROR
            );
        }

        return new Reserved(id, deserializer, payload, converter);
    }

    TlsEcParametersDeserializer deserializer();
    TlsSupportedEllipticCurve toGroup(TlsContext context);

    final class ExplicitPrime implements TlsEcCurveType {
        private static final byte ID = 1;
        static final TlsEcParametersDeserializer DESERIALIZER = new TlsEcParametersDeserializer() {
            @Override
            public Byte id() {
                return ID;
            }

            @Override
            public TlsEcCurveType deserialize(ByteBuffer input) {
                var prime = readBytesBigEndian8(input);
                var a = readBytesBigEndian8(input);
                var b = readBytesBigEndian8(input);
                var encoding = readBytesBigEndian8(input);
                var order = readBytesBigEndian8(input);
                var cofactor = readBytesBigEndian8(input);
                return new ExplicitPrime(prime, a, b, encoding, order, cofactor);
            }
        };

        private final byte[] prime;
        private final byte[] a;
        private final byte[] b;
        private final byte[] encoding;
        private final byte[] order;
        private final byte[] cofactor;

        private ExplicitPrime(byte[] prime, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
            this.prime = prime;
            this.a = a;
            this.b = b;
            this.encoding = encoding;
            this.order = order;
            this.cofactor = cofactor;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public TlsEcParametersDeserializer deserializer() {
            return DESERIALIZER;
        }

        public byte[] prime() {
            return prime;
        }

        public byte[] a() {
            return a;
        }

        public byte[] b() {
            return b;
        }

        public byte[] encoding() {
            return encoding;
        }

        public byte[] order() {
            return order;
        }

        public byte[] cofactor() {
            return cofactor;
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
        public TlsSupportedEllipticCurve toGroup(TlsContext context) {
            return TlsSupportedEllipticCurve.explicitPrime(this);
        }
    }

    final class ExplicitChar2 implements TlsEcCurveType {
        private static final byte ID = 2;
        private static final byte BASIS_TRINOMIAL = 1;
        private static final byte BASIS_PENTANOMIAL = 2;

        static final TlsEcParametersDeserializer DESERIALIZER = new TlsEcParametersDeserializer() {
            @Override
            public Byte id() {
                return ID;
            }

            @Override
            public TlsEcCurveType deserialize(ByteBuffer input) {
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
                        yield new ExplicitChar2(m, basis, k, a, b, encoding, order, cofactor);
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
                        yield new ExplicitChar2(m, basis, k1, k2, k3, a, b, encoding, order, cofactor);
                    }
                    default -> throw new TlsAlert("Unknown basis: " + basis, TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
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

        private ExplicitChar2(int m, byte basis, int k, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
            this(m, basis, k, 0, 0, a, b, encoding, order, cofactor);
        }

        private ExplicitChar2(int m, byte basis, int k1, int k2, int k3, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
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

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public TlsEcParametersDeserializer deserializer() {
            return DESERIALIZER;
        }

        public int m() {
            return m;
        }

        public byte basis() {
            return basis;
        }

        public int k1() {
            return k1;
        }

        public int k2() {
            return k2;
        }

        public int k3() {
            return k3;
        }

        public byte[] a() {
            return a;
        }

        public byte[] b() {
            return b;
        }

        public byte[] encoding() {
            return encoding;
        }

        public byte[] order() {
            return order;
        }

        public byte[] cofactor() {
            return cofactor;
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
                default -> throw new TlsAlert("Unknown basis: " + basis, TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
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
                default -> throw new TlsAlert("Unknown basis: " + basis, TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
            };
        }

        @Override
        public TlsSupportedEllipticCurve toGroup(TlsContext context) {
            return TlsSupportedEllipticCurve.explicitChar2(this);
        }
    }

    final class NamedCurve implements TlsEcCurveType {
        private static final byte ID = 3;
        static final TlsEcParametersDeserializer DESERIALIZER = new TlsEcParametersDeserializer() {
            @Override
            public Byte id() {
                return ID;
            }

            @Override
            public TlsEcCurveType deserialize(ByteBuffer input) {
                var namedGroup = readBigEndianInt16(input);
                return new NamedCurve(namedGroup);
            }
        };

        private final int namedGroup;

        private NamedCurve(int namedGroup) {
            this.namedGroup = namedGroup;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public TlsEcParametersDeserializer deserializer() {
            return DESERIALIZER;
        }

        public int namedGroup() {
            return namedGroup;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, namedGroup);
        }

        @Override
        public int length() {
            return INT16_LENGTH;
        }

        @Override
        public TlsSupportedEllipticCurve toGroup(TlsContext context) {
            return context.getNegotiatedValue(TlsProperty.supportedGroups())
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .stream()
                    .filter(entry -> entry instanceof TlsSupportedEllipticCurve supportedCurve && supportedCurve.accepts(namedGroup))
                    .findFirst()
                    .map(entry -> (TlsSupportedEllipticCurve) entry)
                    .orElseThrow(() -> new TlsAlert("No supported group is an elliptic curve", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        }
    }

    final class Reserved implements TlsEcCurveType {
        private final byte id;
        private final TlsEcParametersDeserializer deserializer;
        private final TlsSerializableProperty payload;
        private final Function<TlsContext, TlsSupportedEllipticCurve> converter;

        private Reserved(byte id, TlsEcParametersDeserializer deserializer, TlsSerializableProperty payload, Function<TlsContext, TlsSupportedEllipticCurve> converter) {
            this.id = id;
            this.deserializer = deserializer;
            this.payload = payload;
            this.converter = converter;
        }

        @Override
        public Byte id() {
            return id;
        }

        @Override
        public TlsEcParametersDeserializer deserializer() {
            if(deserializer == null) {
                throw new TlsAlert(
                        "Negotiated a fake EC curve type",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.INTERNAL_ERROR
                );
            }else {
                return deserializer;
            }
        }

        @Override
        public TlsSupportedEllipticCurve toGroup(TlsContext context) {
            if(converter == null) {
                throw new TlsAlert(
                        "Negotiated a fake EC curve type",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.INTERNAL_ERROR
                );
            }else {
                return converter.apply(context);
            }
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            if(payload != null) {
                payload.serialize(buffer);
            }
        }

        @Override
        public int length() {
            if(payload == null) {
                return 0;
            }else {
                return payload.length();
            }
        }
    }
}
