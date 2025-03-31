package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.name.TlsNameType;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record SNIConfigurableExtension(
        TlsNameType nameType
) implements TlsExtension.Configurable {
    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }

    @Override
    public Optional<? extends TlsExtension.Configured.Client> configureClient(TlsContext context, int messageLength) {
        return configure(context);
    }

    @Override
    public Optional<? extends TlsExtension.Configured.Server> configureServer(TlsContext context, int messageLength) {
        return configure(context);
    }

    private Optional<? extends TlsExtension.Configured.Agnostic> configure(TlsContext context) {
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
    ) implements TlsExtension.Configured.Agnostic {
        private static final TlsExtensionDeserializer<TlsExtension.Configured.Agnostic> DESERIALIZER = (context, _, buffer) -> {
            if(!buffer.hasRemaining()) {
                return switch (context.selectedMode()) {
                    case CLIENT -> context.getNegotiatedValue(TlsProperty.clientExtensions())
                            .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.clientExtensions()))
                            .stream()
                            .filter(entry -> entry instanceof SNIConfigurableExtension.Configured)
                            .map(entry -> (SNIConfigurableExtension.Configured) entry)
                            .findFirst();
                    case SERVER -> throw new BufferUnderflowException();
                };
            }

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
                var extension = new SNIConfigurableExtension.Configured(nameBytes, nameType.get());
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
        public TlsExtensionDeserializer<TlsExtension.Configured.Agnostic> responseDeserializer() {
            return DESERIALIZER;
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.none();
        }
    }
}
