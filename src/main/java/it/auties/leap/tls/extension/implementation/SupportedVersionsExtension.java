package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.TlsGrease;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.extension.TlsExtension.SUPPORTED_VERSIONS_TYPE;
import static it.auties.leap.tls.extension.TlsExtension.SUPPORTED_VERSIONS_VERSIONS;
import static it.auties.leap.tls.util.BufferUtils.*;

public sealed class SupportedVersionsExtension {
    private static final Integer[] GREASE_IDS = TlsGrease.values()
            .stream()
            .map(grease -> grease.versionId().value())
            .toArray(Integer[]::new);

    public static TlsExtension.Client of() {
        return ClientConfigurable.INSTANCE;
    }

    public static TlsExtension.Client of(List<TlsVersionId> versions) {
        return new Client(versions);
    }

    public static TlsExtension.Server of(TlsVersion version) {
        return new Server(version);
    }

    public int type() {
        return SUPPORTED_VERSIONS_TYPE;
    }

    public List<TlsVersion> versions() {
        return SUPPORTED_VERSIONS_VERSIONS;
    }

    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.some(GREASE_IDS);
    }

    public Optional<? extends TlsExtension.Server> deserializeClient(TlsContext context, int type, ByteBuffer buffer) {
        var major = readBigEndianInt8(buffer);
        var minor = readBigEndianInt8(buffer);
        var versionId = TlsVersionId.of(major, minor);
        var supportedVersions = context.getAdvertisedValue(TlsContextualProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsVersion::id, Function.identity()));
        var supportedVersion = supportedVersions.get(versionId);
        if(supportedVersion == null) {
            throw new TlsAlert("Remote tried to negotiate a version that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
        var extension = new Server(supportedVersion);
        return Optional.of(extension);
    }

    public Optional<? extends TlsExtension.Client> deserializeServer(TlsContext context, int type, ByteBuffer buffer) {
        var payloadSize = readBigEndianInt8(buffer);
        var versions = new ArrayList<TlsVersionId>();
        try (var _ = scopedRead(buffer, payloadSize)) {
            var versionsSize = payloadSize / INT16_LENGTH;
            for (var i = 0; i < versionsSize; i++) {
                var major = readBigEndianInt8(buffer);
                var minor = readBigEndianInt8(buffer);
                var versionId = TlsVersionId.of(major, minor);
                versions.add(versionId);
            }
        }
        var extension = new Client(versions);
        return Optional.of(extension);
    }

    private static final class ClientConfigurable extends SupportedVersionsExtension implements TlsExtension.Client {
        private static final ClientConfigurable INSTANCE = new ClientConfigurable();

        private ClientConfigurable() {

        }

        @Override
        public int hashCode() {
            return type();
        }

        @Override
        public String toString() {
            return "SupportedVersionsExtension[supportedVersions=<configurable>]";
        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return switch (context.localConnectionState().type()) {
                case CLIENT -> {
                    var supportedVersions = new ArrayList<TlsVersionId>();
                    context.getAdvertisedValue(TlsContextualProperty.version())
                            .orElseThrow(() -> new TlsAlert("Missing negotiable property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                            .forEach(version -> supportedVersions.add(version.id()));
                    var grease = context.extensions()
                            .stream()
                            .anyMatch(entry -> TlsGrease.isGrease(entry.type()));
                    if (grease) {
                        supportedVersions.add(TlsGrease.greaseRandom());
                    }
                    yield new SupportedVersionsExtension.Client(supportedVersions);
                }

                case SERVER -> {
                    var version = context.getAdvertisedValue(TlsContextualProperty.version())
                            .orElseThrow(() -> new TlsAlert("Missing negotiable property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                            .stream()
                            .reduce((first, second) -> first.id().value() > second.id().value() ? first : second)
                            .orElseThrow(() -> new TlsAlert("Missing negotiable property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                    yield new SupportedVersionsExtension.Server(version);
                }
            };
        }
    }

    private static final class Client extends SupportedVersionsExtension implements TlsExtension.Client, TlsExtensionPayload {
        private final List<TlsVersionId> supportedVersions;

        private Client(List<TlsVersionId> supportedVersions) {
            this.supportedVersions = supportedVersions;
        }

        @Override
        public void serializePayload(ByteBuffer buffer) {
            var payloadSize = supportedVersions.size() * INT16_LENGTH;
            writeBigEndianInt8(buffer, payloadSize);
            for (var tlsVersion : supportedVersions) {
                writeBigEndianInt8(buffer, tlsVersion.major());
                writeBigEndianInt8(buffer, tlsVersion.minor());
            }
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            // supportedVersions is already set in tls context
        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }

        @Override
        public int payloadLength() {
            return INT8_LENGTH + INT16_LENGTH * supportedVersions.size();
        }


        @Override
        public boolean equals(Object o) {
            return o instanceof SupportedVersionsExtension.Client client
                    && Objects.equals(supportedVersions, client.supportedVersions);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(supportedVersions);
        }

        @Override
        public String toString() {
            return "SupportedVersionsExtension[" +
                    "supportedVersions=" + supportedVersions + ']';
        }
    }


    private static final class Server extends SupportedVersionsExtension implements TlsExtension.Server, TlsExtensionPayload {
        private final TlsVersion supportedVersion;

        private Server(TlsVersion supportedVersion) {
            this.supportedVersion = supportedVersion;
        }

        @Override
        public void serializePayload(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, supportedVersion.id().major());
            writeBigEndianInt8(buffer, supportedVersion.id().minor());
        }

        @Override
        public int payloadLength() {
            return INT16_LENGTH;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            context.addNegotiatedValue(TlsContextualProperty.version(), supportedVersion);
        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof SupportedVersionsExtension.Server server
                    && supportedVersion == server.supportedVersion;
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(supportedVersion);
        }

        @Override
        public String toString() {
            return "SupportedVersionsExtension[" +
                    "supportedVersion=" + supportedVersion + ']';
        }
    }
}
