package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.util.sun.IPAddressUtil;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Predicate;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class SNIExtension {
    private static final TlsExtensionDeserializer DECODER = (_, _, _, buffer) -> {
        var listLength = readBigEndianInt16(buffer);
        if(listLength == 0) {
            return Optional.empty();
        }

        try(var _ = scopedRead(buffer, listLength)) {
            var nameTypeId = readBigEndianInt8(buffer);
            var nameType = NameType.of(nameTypeId);
            if(nameType.isEmpty()) {
                return Optional.empty();
            }

            var nameBytes = readBytesBigEndian16(buffer);
            var extension = new Concrete(nameBytes, nameType.get());
            return Optional.of(extension);
        }
    };

    public static TlsExtension instance() {
        return Configurable.INSTANCE;
    }

    private static final class Concrete extends SNIExtension implements TlsConcreteExtension {
        private final byte[] name;
        private final NameType nameType;

        private Concrete(byte[] name, NameType nameType) {
            this.name = name;
            this.nameType = nameType;
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, INT8_LENGTH + INT16_LENGTH + name.length);
            writeBigEndianInt8(buffer, nameType.id());
            writeBytesBigEndian16(buffer, name);
        }

        @Override
        public int extensionPayloadLength() {
            return INT16_LENGTH + INT8_LENGTH + INT16_LENGTH + name.length;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {

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

        @Override
        public boolean equals(Object o) {
            return o instanceof SNIExtension.Concrete concrete
                    && Objects.deepEquals(name, concrete.name)
                    && nameType == concrete.nameType;
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

    private static final class Configurable extends SNIExtension implements TlsConfigurableExtension {
        private static final SNIExtension.Configurable INSTANCE = new SNIExtension.Configurable();
        private Configurable() {

        }

        @Override
        public Optional<? extends TlsConcreteExtension> newInstance(TlsContext context, int messageLength) {
            var type = NameType.HOST_NAME;
            return context.address()
                    .map(InetSocketAddress::getHostName)
                    .filter(type::isValid)
                    .map(hostName -> new SNIExtension.Concrete(hostName.getBytes(StandardCharsets.US_ASCII), type));
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.none();
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

    // Is it a good idea to move this to a public location?
    // Technically there could be one day more supported values as the spec lists [1, 255] as reserved for future use
    private enum NameType {
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
