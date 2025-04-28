package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.supplemental.TlsName;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ServerNameExtension(
        TlsName.Type name
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
        return switch (name) {
            case HOST_NAME -> {
                var hostname = context.address()
                        .map(InetSocketAddress::getHostName)
                        .orElse(null);
                if(hostname == null) {
                    yield Optional.empty();
                }

                var tlsName = TlsName.hostName(hostname);
                var extension = new Configured(List.of(tlsName), tlsName.length());
                yield Optional.of(extension);
            }
        };
    }

    @Override
    public int type() {
        return SERVER_NAME_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SERVER_NAME_VERSIONS;
    }

    // TODO: Split in client and server
    private record Configured(
            List<TlsName> names,
            int namesLength
    ) implements TlsExtension.Configured.Agnostic {
        @Override
        public void serializePayload(ByteBuffer buffer) {
            if(namesLength > 0) {
                writeBigEndianInt16(buffer, namesLength);
                for(var name : names) {
                    name.serialize(buffer);
                }
            }
        }

        @Override
        public int payloadLength() {
            return namesLength > 0 ? INT16_LENGTH + namesLength : 0;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            if(source == TlsSource.REMOTE) {
                // TODO: Check if name matches local
            }
        }

        @Override
        public Optional<? extends Agnostic> deserialize(TlsContext context, int type, ByteBuffer buffer) {
            if(!buffer.hasRemaining()) {
                return switch (context.localConnectionState().type()) {
                    case CLIENT -> context.getNegotiatedValue(TlsProperty.clientExtensions())
                            .orElseThrow(() -> new TlsAlert("Missing negotiated property: clientExtensions", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                            .stream()
                            .filter(entry -> entry instanceof ServerNameExtension.Configured)
                            .map(entry -> (ServerNameExtension.Configured) entry)
                            .findFirst();
                    case SERVER -> throw new BufferUnderflowException();
                };
            }

            var listLength = readBigEndianInt16(buffer);
            if(listLength == 0) {
                return Optional.empty();
            }

            try(var _ = scopedRead(buffer, listLength)) {
                var names = new ArrayList<TlsName>();
                while (buffer.hasRemaining()) {
                    var name = TlsName.of(buffer)
                            .orElseThrow(() -> new TlsAlert("Invalid server name type", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
                    names.add(name);
                }
                var extension = new ServerNameExtension.Configured(names, listLength);
                return Optional.of(extension);
            }
        }

        @Override
        public int type() {
            return SERVER_NAME_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return SERVER_NAME_VERSIONS;
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.none();
        }
    }
}
