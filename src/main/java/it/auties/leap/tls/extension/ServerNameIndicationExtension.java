package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.util.IPAddressUtil;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

import static it.auties.leap.tls.util.BufferHelper.*;

public final class ServerNameIndicationExtension implements TlsExtension.Implementation {
    private final byte[] name;
    private final NameType nameType;
    ServerNameIndicationExtension(byte[] name, NameType nameType) {
        this.name = name;
        this.nameType = nameType;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        var listLength = INT8_LENGTH + INT16_LENGTH + name.length;
        writeLittleEndianInt16(buffer, listLength);

        writeLittleEndianInt8(buffer, nameType.id());

        writeBytesLittleEndian16(buffer, name);
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + INT8_LENGTH + INT16_LENGTH + name.length;
    }

    @Override
    public int extensionType() {
        return TlsExtensions.SERVER_NAME_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.SERVER_NAME_VERSIONS;
    }

    public byte[] name() {
        return name;
    }

    public NameType nameType() {
        return nameType;
    }

    enum NameType {
        HOST_NAME((byte) 0, IPAddressUtil::isHostName);

        private static final Map<Byte, NameType> VALUES = Map.of(
                HOST_NAME.id(), HOST_NAME
        );
        public static Optional<NameType> of(byte id) {
            return Optional.ofNullable(VALUES.get(id));
        }

        private final byte id;
        private final Predicate<String> checker;
        NameType(byte id, Predicate<String> checker) {
            this.id = id;
            this.checker = checker;
        }

        public byte id() {
            return id;
        }

        public boolean isValid(String value) {
            return checker.test(value);
        }
    }
}
