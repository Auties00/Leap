package it.auties.leap.tls.key;

import it.auties.leap.tls.*;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static it.auties.leap.tls.TlsRecord.*;

public sealed interface TlsServerKey {
    void serialize(ByteBuffer buffer);

    int length();

    static TlsServerKey of(TlsCipher cipher, ByteBuffer buffer) {
        return switch (cipher.keyExchange()) {
            case DHE -> {
                var p = readBytes16(buffer);
                var g = readBytes16(buffer);
                var s = readBytes16(buffer);
                yield new DHE(p, g, s);
            }
            case ECCPWD -> {
                var namedGroupId = readInt16(buffer);
                var namedGroup = TlsSupportedGroup.of(namedGroupId)
                        .orElseThrow(() -> new TlsSpecificationException("Unknown NamedCurve for id: " + namedGroupId, URI.create("https://www.ietf.org/rfc/rfc8422.txt"), "5.1.1"));
                var element = readBytes16(buffer);
                var scalar = readBytes16(buffer);
                yield new ECCPWD(namedGroup, element, scalar);
            }
            case ECDHE -> {
                var curveTypeId = readInt8(buffer);
                var curveType = TLSEcType.of(curveTypeId)
                        .orElseThrow(() -> new TlsSpecificationException("Unknown ECCurveType for id: " + curveTypeId, URI.create("https://www.ietf.org/rfc/rfc8422.txt"), "5.4."));
                yield switch (curveType) {
                    case NAMED_CURVE -> {
                        var namedGroupId = readInt16(buffer);
                        var namedGroup = TlsSupportedGroup.of(namedGroupId)
                                .orElseThrow(() -> new TlsSpecificationException("Unknown NamedCurve for id: " + namedGroupId, URI.create("https://www.ietf.org/rfc/rfc8422.txt"), "5.1.1"));
                        var ecdheParameters = new ECDHE.ECDHEParameters.NamedCurve(namedGroup);
                        var publicKey = readBytes8(buffer);
                        yield new ECDHE(curveType, ecdheParameters, publicKey);
                    }
                    case EXPLICIT_PRIME -> {
                        var primeP = readBytes8(buffer);
                        var a = readBytes8(buffer);
                        var b = readBytes8(buffer);
                        var curve = new ECDHE.ECCurve(a, b);
                        var base = readBytes8(buffer);
                        var order = readBytes8(buffer);
                        var cofactor = readBytes8(buffer);
                        var ecdheParameters = new ECDHE.ECDHEParameters.ExplicitPrime(primeP, curve, base, order, cofactor);
                        var publicKey = readBytes8(buffer);
                        yield new ECDHE(curveType, ecdheParameters, publicKey);
                    }
                    case EXPLICIT_CHAR2 -> {
                        var m = Short.toUnsignedInt(readBuffer(buffer, INT16_LENGTH).order(ByteOrder.BIG_ENDIAN).getShort());
                        var basisType = readInt8(buffer);
                        var basisParameters = switch (basisType) {
                            case ECDHE.ECDHEParameters.ExplicitChar2.BasisParameters.Trinomial.ID -> {
                                var k1 = readBytes8(buffer);
                                yield new ECDHE.ECDHEParameters.ExplicitChar2.BasisParameters.Trinomial(k1);
                            }
                            case ECDHE.ECDHEParameters.ExplicitChar2.BasisParameters.Pentomial.ID -> {
                                var k1 = readBytes8(buffer);
                                var k2 = readBytes8(buffer);
                                var k3 = readBytes8(buffer);
                                yield new ECDHE.ECDHEParameters.ExplicitChar2.BasisParameters.Pentomial(k1, k2, k3);
                            }
                            default ->
                                    throw new TlsSpecificationException("Unexpected basis type: " + basisType, URI.create("https://datatracker.ietf.org/doc/rfc4492/"), "5.4");
                        };
                        var a = readBytes8(buffer);
                        var b = readBytes8(buffer);
                        var curve = new ECDHE.ECCurve(a, b);
                        var base = readBytes8(buffer);
                        var order = readBytes8(buffer);
                        var cofactor = readBytes8(buffer);
                        var ecdheParameters = new ECDHE.ECDHEParameters.ExplicitChar2(m, basisParameters, curve, base, order, cofactor);
                        var publicKey = readBytes8(buffer);
                        yield new ECDHE(curveType, ecdheParameters, publicKey);
                    }
                };
            }
            case GOSTR341112_256 -> {
                var paramSet = readBytes8(buffer);
                var publicKey = readBytes16(buffer);
                yield new GOSTR(paramSet, publicKey);
            }
            case PSK -> {
                var identityHint = readBytes16(buffer);
                yield new PSK(identityHint);
            }
            case SRP -> {
                var n = readBytes16(buffer);
                var g = readBytes16(buffer);
                var s = readBytes16(buffer);
                var b = readBytes16(buffer);
                yield new SRP(n, g, s, b);
            }
            case DH, ECDH, KRB5, NULL, RSA ->
                    throw new TlsSpecificationException("ServerKeyExchange is not necessary for %s".formatted(cipher.keyExchange()), URI.create("https://www.ietf.org/rfc/rfc5246.txt"), "7.4.3");
        };
    }

    record DHE(byte[] p, byte[] g, byte[] y) implements TlsServerKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, p);
            writeBytes16(buffer, g);
            writeBytes16(buffer, y);
        }

        @Override
        public int length() {
            return INT16_LENGTH + p.length
                    + INT16_LENGTH + g.length
                    + INT16_LENGTH + y.length;
        }
    }

    record ECCPWD(TlsSupportedGroup group, byte[] element, byte[] scalar) implements TlsServerKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeInt16(buffer, group.id());
            writeBytes16(buffer, element);
            writeBytes16(buffer, scalar);
        }

        @Override
        public int length() {
            return INT16_LENGTH
                    + INT16_LENGTH + element.length
                    + INT16_LENGTH + scalar.length;
        }
    }

    record ECDHE(TLSEcType type, ECDHE.ECDHEParameters parameters, byte[] rawPublicKey) implements TlsServerKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeInt8(buffer, type.id());
            parameters.serialize(buffer);
            writeBytes8(buffer, rawPublicKey);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + parameters.length()
                    + INT8_LENGTH + rawPublicKey.length;
        }

        public sealed interface ECDHEParameters {
            void serialize(ByteBuffer buffer);

            int length();

            record NamedCurve(TlsSupportedGroup group) implements ECDHE.ECDHEParameters {
                @Override
                public void serialize(ByteBuffer buffer) {
                    writeInt16(buffer, group.id());
                }

                @Override
                public int length() {
                    return INT16_LENGTH;
                }
            }

            record ExplicitPrime(byte[] primeP, ECDHE.ECCurve curve, byte[] base, byte[] order,
                                 byte[] cofactor) implements ECDHE.ECDHEParameters {
                @Override
                public void serialize(ByteBuffer buffer) {
                    writeBytes8(buffer, primeP);
                    curve.serialize(buffer);
                    writeBytes8(buffer, base);
                    writeBytes8(buffer, order);
                    writeBytes8(buffer, cofactor);
                }

                @Override
                public int length() {
                    return INT8_LENGTH + primeP.length
                            + curve.length()
                            + INT8_LENGTH + base.length
                            + INT8_LENGTH + order.length
                            + INT8_LENGTH + cofactor.length;
                }
            }

            record ExplicitChar2(int m, ECDHE.ECDHEParameters.ExplicitChar2.BasisParameters basisParameters,
                                 ECDHE.ECCurve curve, byte[] base, byte[] order,
                                 byte[] cofactor) implements ECDHE.ECDHEParameters {
                @Override
                public void serialize(ByteBuffer buffer) {
                    var mBuffer = ByteBuffer.allocate(INT16_LENGTH)
                            .order(ByteOrder.BIG_ENDIAN)
                            .putShort((short) m);
                    mBuffer.flip();
                    writeBuffer(buffer, mBuffer);
                    curve.serialize(buffer);
                    writeBytes8(buffer, base);
                    writeBytes8(buffer, order);
                    writeBytes8(buffer, cofactor);
                }

                @Override
                public int length() {
                    return INT16_LENGTH
                            + curve.length()
                            + INT8_LENGTH + base.length
                            + INT8_LENGTH + order.length
                            + INT8_LENGTH + cofactor.length;
                }

                sealed interface BasisParameters {
                    byte id();

                    TlsEcBasisType type();

                    void serialize(ByteBuffer buffer);

                    int length();

                    record Trinomial(byte[] k) implements ExplicitChar2.BasisParameters {
                        private static final byte ID = 2;

                        @Override
                        public byte id() {
                            return ID;
                        }

                        @Override
                        public TlsEcBasisType type() {
                            return TlsEcBasisType.TRINOMIAL;
                        }

                        @Override
                        public void serialize(ByteBuffer buffer) {
                            writeBytes8(buffer, k);
                        }

                        @Override
                        public int length() {
                            return INT8_LENGTH + k.length;
                        }
                    }

                    record Pentomial(byte[] k1, byte[] k2, byte[] k3) implements ExplicitChar2.BasisParameters {
                        private static final byte ID = 3;

                        @Override
                        public byte id() {
                            return ID;
                        }

                        @Override
                        public TlsEcBasisType type() {
                            return TlsEcBasisType.PENTOMIAL;
                        }

                        @Override
                        public void serialize(ByteBuffer buffer) {
                            writeBytes8(buffer, k1);
                            writeBytes8(buffer, k2);
                            writeBytes8(buffer, k3);
                        }

                        @Override
                        public int length() {
                            return INT8_LENGTH + k1.length
                                    + INT8_LENGTH + k2.length
                                    + INT8_LENGTH + k3.length;
                        }
                    }
                }
            }
        }

        record ECCurve(byte[] a, byte[] b) {
            public void serialize(ByteBuffer buffer) {
                writeBytes8(buffer, a);
                writeBytes8(buffer, b);
            }

            public int length() {
                return INT8_LENGTH + a.length
                        + INT8_LENGTH + b.length;
            }
        }
    }

    record GOSTR(byte[] paramSet, byte[] rawPublicKey) implements TlsServerKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes8(buffer, paramSet);
            writeBytes16(buffer, rawPublicKey);
        }

        @Override
        public int length() {
            return INT8_LENGTH + paramSet.length
                    + INT16_LENGTH + rawPublicKey.length;
        }
    }

    record PSK(byte[] identityHint) implements TlsServerKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, identityHint);
        }

        @Override
        public int length() {
            return INT16_LENGTH + identityHint.length;
        }
    }

    record SRP(byte[] n, byte[] g, byte[] s, byte[] b) implements TlsServerKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, n);
            writeBytes16(buffer, g);
            writeBytes16(buffer, s);
            writeBytes16(buffer, b);
        }

        @Override
        public int length() {
            return INT16_LENGTH + n.length
                    + INT16_LENGTH + g.length
                    + INT16_LENGTH + s.length
                    + INT16_LENGTH + b.length;
        }
    }
}
