package it.auties.leap.tls.supplemental;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;
import it.auties.leap.tls.util.sun.IPAddressUtil;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsName extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty {
    static HostName hostName(String name) {
        if(!IPAddressUtil.isHostName(name)) {
            throw new TlsAlert("Invalid host name: " + name, TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new HostName(name.getBytes(StandardCharsets.US_ASCII));
    }

    @SuppressWarnings("SwitchStatementWithTooFewBranches")
    static Optional<TlsName> of(ByteBuffer buffer) {
        var nameTypeId = readBigEndianInt8(buffer);
        return switch (nameTypeId) {
            case HostName.ID -> Optional.of(HostName.of(buffer));
            default -> Optional.empty();
        };
    }

    Type type();

    @Override
    default void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
    }

    @Override
    default int length() {
        return INT8_LENGTH;
    }

    final class HostName implements TlsName {
        private static final int ID = 0;

        private final byte[] name;

        private HostName(byte[] name) {
            this.name = name;
        }

        public static HostName of(ByteBuffer buffer) {
            var name = readBytesBigEndian16(buffer);
            return new HostName(name);
        }

        public byte[] name() {
            return name;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            TlsName.super.serialize(buffer);
            writeBytesBigEndian16(buffer, name);
        }

        @Override
        public int length() {
            return TlsName.super.length()
                    + INT16_LENGTH + name.length;
        }

        @Override
        public Type type() {
            return Type.HOST_NAME;
        }
    }

    enum Type {
        HOST_NAME,
    }
}
