package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.name.TlsNameType;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record SNIConfigurableExtension(
        TlsNameType nameType
) implements TlsConfigurableClientExtension, TlsConfigurableServerExtension {
    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }

    @Override
    public Optional<? extends TlsConfiguredExtension> configure(TlsContext context, int messageLength) {
        return switch (nameType) {
            case HOST_NAME -> {
                var hostname = context.address()
                        .map(InetSocketAddress::getHostName)
                        .orElse(null);
                if(hostname == null || !nameType.accepts(hostname)) {
                    yield Optional.empty();
                }

                var name = hostname.getBytes(StandardCharsets.US_ASCII);
                yield Optional.of(new Configured(name, nameType));
            }
        };
    }

    @Override
    public int extensionType() {
        return SERVER_NAME_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SERVER_NAME_VERSIONS;
    }

    private record Configured(
            byte[] name,
            TlsNameType nameType
    ) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension {
        private static final TlsExtensionDeserializer DESERIALIZER = (_, _, buffer) -> {
            var listLength = readBigEndianInt16(buffer);
            if(listLength == 0) {
                return Optional.empty();
            }

            try(var _ = scopedRead(buffer, listLength)) {
                var nameTypeId = readBigEndianInt8(buffer);
                var nameType = TlsNameType.of(nameTypeId);
                if(nameType.isEmpty()) {
                    return Optional.empty();
                }

                var nameBytes = readBytesBigEndian16(buffer);
                // TODO: Check if name matches local
                var extension = new Configured(nameBytes, nameType.get());
                return Optional.of(extension);
            }
        };

        @Override
        public void serializePayload(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, INT8_LENGTH + INT16_LENGTH + name.length);
            writeBigEndianInt8(buffer, nameType.id());
            writeBytesBigEndian16(buffer, name);
        }

        @Override
        public int payloadLength() {
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
        public TlsExtensionDeserializer deserializer() {
            return DESERIALIZER;
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.none();
        }
    }
}
