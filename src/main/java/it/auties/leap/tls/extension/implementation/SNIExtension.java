package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.util.AddressUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Predicate;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class SNIExtension {
    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer() {
        @Override
        public Optional<? extends TlsExtension.Concrete> deserialize(ByteBuffer buffer, int type, TlsMode mode) {
            var listLength = readBigEndianInt16(buffer);
            if(listLength == 0) {
                return Optional.empty();
            }

            try(var _ = scopedRead(buffer, listLength)) {
                var nameTypeId = readBigEndianInt8(buffer);
                var nameType = NameType.of(nameTypeId)
                        .orElseThrow(() -> new IllegalArgumentException("Unknown name type: " + nameTypeId));
                var nameBytes = readBytesBigEndian16(buffer);
                var extension = new Concrete(nameBytes, nameType);
                return Optional.of(extension);
            }
        }

        @Override
        public Class<? extends TlsExtension.Concrete> toConcreteType(TlsMode mode) {
            return Concrete.class;
        }
    };

    public static final class Concrete extends SNIExtension implements TlsExtension.Concrete {
        private final byte[] name;
        private final NameType nameType;

        public Concrete(byte[] name, NameType nameType) {
            this.name = name;
            this.nameType = nameType;
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {
            var listLength = INT8_LENGTH + INT16_LENGTH + name.length;
            writeBigEndianInt16(buffer, listLength);

            writeBigEndianInt8(buffer, nameType.id());

            writeBytesBigEndian16(buffer, name);
        }

        @Override
        public int extensionPayloadLength() {
            return INT16_LENGTH + INT8_LENGTH + INT16_LENGTH + name.length;
        }

        @Override
        public int extensionType() {
            return SERVER_NAME_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return SERVER_NAME_VERSIONS;
        }

        @Override
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }

        public byte[] name() {
            return name;
        }

        public NameType nameType() {
            return nameType;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (SNIExtension.Concrete) obj;
            return Arrays.equals(this.name, that.name) &&
                    Objects.equals(this.nameType, that.nameType);
        }

        @Override
        public int hashCode() {
            return Objects.hash(Arrays.hashCode(name), nameType);
        }

        @Override
        public String toString() {
            return "ServerNameIndicationExtension[" +
                    "name=" + new String(name, StandardCharsets.US_ASCII) + ", " +
                    "nameType=" + nameType.name() + ']';
        }

    }

    public static final class Configurable extends SNIExtension implements TlsExtension.Configurable {
        private static final SNIExtension.Configurable INSTANCE = new SNIExtension.Configurable();
        private Configurable() {

        }

        public static SNIExtension.Configurable instance() {
            return INSTANCE;
        }

        @Override
        public Optional<? extends TlsExtension.Concrete> newInstance(TlsContext context) {
            var hostname = context.remoteAddress()
                    .map(InetSocketAddress::getHostName)
                    .orElse(null);
            if(hostname == null) {
                return Optional.empty();
            }

            var type = NameType.HOST_NAME;
            if(!type.isValid(hostname)) {
                return Optional.empty();
            }

            var result = new SNIExtension.Concrete(hostname.getBytes(StandardCharsets.US_ASCII), type);
            return Optional.of(result);
        }

        @Override
        public Dependencies dependencies() {
            return Dependencies.none();
        }

        @Override
        public int extensionType() {
            return SERVER_NAME_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return SERVER_NAME_VERSIONS;
        }

        @Override
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }
    }

    public enum NameType {
        HOST_NAME((byte) 0, AddressUtils::isHostName);

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
