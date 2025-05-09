package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.supplemental.TlsName;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.extension.TlsExtension.*;
import static it.auties.leap.tls.util.BufferUtils.*;

public sealed class SNIExtension {
    public static TlsExtension.Client of(TlsName.Type type) {
        return new ClientConfigurable(type);
    }

    public static TlsExtension.Client of(TlsName name) {
        return new Client(name);
    }

    public static TlsExtension.Server of(List<TlsName> names) {
        var namesLength = names.stream()
                .mapToInt(TlsName::length)
                .sum();
        return new SNIExtension.Server(names, namesLength);
    }

    public int type() {
        return SERVER_NAME_TYPE;
    }

    public List<TlsVersion> versions() {
        return SERVER_NAME_VERSIONS;
    }

    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }

    public Optional<? extends TlsExtension.Server> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        var listLength = readBigEndianInt16(source);
        if(listLength == 0) {
            return Optional.empty();
        }

        try(var _ = scopedRead(source, listLength)) {
            var names = new ArrayList<TlsName>();
            while (source.hasRemaining()) {
                var name = TlsName.of(source).orElseThrow(() -> new TlsAlert(
                        "Invalid server name type",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.ILLEGAL_PARAMETER
                ));
                names.add(name);
            }
            var extension = new Server(names, listLength);
            return Optional.of(extension);
        }
    }

    public Optional<? extends TlsExtension.Client> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        return context.extensions()
                .stream()
                .filter(entry -> entry instanceof SNIExtension.Client)
                .map(entry -> (SNIExtension.Client) entry)
                .findFirst();
    }

    private static final class ClientConfigurable extends SNIExtension implements TlsExtension.Client {
        private final TlsName.Type type;

        private ClientConfigurable(TlsName.Type type) {
            this.type = type;
        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return switch (type) {
                case HOST_NAME -> {
                    var hostname = context.address()
                            .map(InetSocketAddress::getHostName)
                            .orElse(null);
                    yield new SNIExtension.Client(TlsName.hostName(hostname));
                }
            };
        }
    }

    private static final class Client extends SNIExtension implements TlsExtension.Client, TlsExtensionPayload {
        private final TlsName name;

        private Client(TlsName name) {
            this.name = name;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {

        }

        @Override
        public void serializePayload(ByteBuffer buffer) {
            name.serialize(buffer);
        }

        @Override
        public int payloadLength() {
            return name.length();
        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }
    }

    private static final class Server extends SNIExtension implements TlsExtension.Server, TlsExtensionPayload {
        private final List<TlsName> names;
        private final int namesLength;

        Server(List<TlsName> names, int namesLength) {
            this.names = names;
            this.namesLength = namesLength;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {

        }

        @Override
        public void serializePayload(ByteBuffer buffer) {
            if (namesLength > 0) {
                writeBigEndianInt16(buffer, namesLength);
                for (var name : names) {
                    name.serialize(buffer);
                }
            }
        }

        @Override
        public int payloadLength() {
            return namesLength > 0 ? INT16_LENGTH + namesLength : 0;
        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }
    }
}
