package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static it.auties.leap.tls.BufferHelper.*;

public final class EcDheServerKeyExchange extends TlsKeyExchange.Server {
    private final ECDHEParameters parameters;
    private final byte[] rawPublicKey;

    public EcDheServerKeyExchange(ECDHEParameters parameters, byte[] rawPublicKey) {
        this.parameters = parameters;
        this.rawPublicKey = rawPublicKey;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        parameters.serialize(buffer);
        writeBytesLittleEndian8(buffer, rawPublicKey);
    }

    @Override
    public int length() {
        return INT8_LENGTH
                + parameters.length()
                + INT8_LENGTH + rawPublicKey.length;
    }

    public ECDHEParameters parameters() {
        return parameters;
    }

    public byte[] rawPublicKey() {
        return rawPublicKey;
    }

    public sealed interface ECDHEParameters {
        default void serialize(ByteBuffer buffer) {
            writeLittleEndianInt8(buffer, id());
        }

        byte id();

        int length();

        record ExplicitPrime(byte[] primeP, ECCurve curve, byte[] base, byte[] order,
                             byte[] cofactor) implements ECDHEParameters {
            @Override
            public byte id() {
                return 1;
            }

            @Override
            public void serialize(ByteBuffer buffer) {
                ECDHEParameters.super.serialize(buffer);
                writeBytesLittleEndian8(buffer, primeP);
                curve.serialize(buffer);
                writeBytesLittleEndian8(buffer, base);
                writeBytesLittleEndian8(buffer, order);
                writeBytesLittleEndian8(buffer, cofactor);
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

        record ExplicitChar2(int m, BasisParameters basisParameters, ECCurve curve, byte[] base,
                             byte[] order, byte[] cofactor) implements ECDHEParameters {
            @Override
            public byte id() {
                return 2;
            }

            @Override
            public void serialize(ByteBuffer buffer) {
                ECDHEParameters.super.serialize(buffer);
                var mBuffer = ByteBuffer.allocate(INT16_LENGTH)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putShort((short) m);
                mBuffer.flip();
                writeBuffer(buffer, mBuffer);
                curve.serialize(buffer);
                writeBytesLittleEndian8(buffer, base);
                writeBytesLittleEndian8(buffer, order);
                writeBytesLittleEndian8(buffer, cofactor);
            }

            @Override
            public int length() {
                return INT16_LENGTH
                        + curve.length()
                        + INT8_LENGTH + base.length
                        + INT8_LENGTH + order.length
                        + INT8_LENGTH + cofactor.length;
            }

            sealed

            interface BasisParameters {
                byte id();

                void serialize(ByteBuffer buffer);

                int length();

                record Trinomial(byte[] k) implements BasisParameters {
                    private static final byte ID = 2;

                    @Override
                    public byte id() {
                        return ID;
                    }

                    @Override
                    public void serialize(ByteBuffer buffer) {
                        writeBytesLittleEndian8(buffer, k);
                    }

                    @Override
                    public int length() {
                        return INT8_LENGTH + k.length;
                    }
                }

                record Pentomial(byte[] k1, byte[] k2, byte[] k3) implements BasisParameters {
                    private static final byte ID = 3;

                    @Override
                    public byte id() {
                        return ID;
                    }

                    @Override
                    public void serialize(ByteBuffer buffer) {
                        writeBytesLittleEndian8(buffer, k1);
                        writeBytesLittleEndian8(buffer, k2);
                        writeBytesLittleEndian8(buffer, k3);
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

        record NamedCurve(TlsSupportedGroup group) implements ECDHEParameters {
            @Override
            public byte id() {
                return 3;
            }

            @Override
            public void serialize(ByteBuffer buffer) {
                ECDHEParameters.super.serialize(buffer);
                writeLittleEndianInt16(buffer, group.id());
            }

            @Override
            public int length() {
                return INT16_LENGTH;
            }
        }

        non-sealed abstract class Reserved implements ECDHEParameters {
            private final byte id;

            public Reserved(byte id) {
                this.id = id;
            }

            @Override
            public void serialize(ByteBuffer buffer) {
                ECDHEParameters.super.serialize(buffer);
            }

            @Override
            public int length() {
                return INT16_LENGTH;
            }

            @Override
            public byte id() {
                return id;
            }
        }

        record ECCurve(byte[] a, byte[] b) {
            public void serialize(ByteBuffer buffer) {
                writeBytesLittleEndian8(buffer, a);
                writeBytesLittleEndian8(buffer, b);
            }

            public int length() {
                return INT8_LENGTH + a.length
                        + INT8_LENGTH + b.length;
            }
        }
    }
}
