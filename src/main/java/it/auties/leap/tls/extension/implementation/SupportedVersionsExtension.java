package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.TlsGREASE;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SupportedVersionsExtension implements TlsExtension.Configurable {
    private static final SupportedVersionsExtension INSTANCE = new SupportedVersionsExtension();

    private SupportedVersionsExtension() {

    }

    public static SupportedVersionsExtension instance() {
        return INSTANCE;
    }

    @Override
    public int type() {
        return SUPPORTED_VERSIONS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SUPPORTED_VERSIONS_VERSIONS;
    }

    @Override
    public Optional<? extends TlsExtension.Configured.Client> configureClient(TlsContext context, int messageLength) {
        var supportedVersions = new ArrayList<TlsVersionId>();
        context.getNegotiableValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()))
                .forEach(version -> supportedVersions.add(version.id()));
        var grease = context.getNegotiableValue(TlsProperty.clientExtensions())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.clientExtensions()))
                .stream()
                .anyMatch(entry -> TlsGREASE.isGrease(entry.type()));
        if (grease) {
            supportedVersions.add(TlsGREASE.greaseRandom());
        }
        return Optional.of(new ConfiguredClient(supportedVersions));
    }

    @Override
    public Optional<? extends TlsExtension.Configured.Server> configureServer(TlsContext context, int messageLength) {
        var version = context.getNegotiableValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()))
                .stream()
                .reduce((first, second) -> first.id().value() > second.id().value() ? first : second)
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()));
        return Optional.of(new ConfiguredServer(version));
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        var values = TlsGREASE.values()
                .stream()
                .map(grease -> grease.versionId().value())
                .toArray(Integer[]::new);
        return TlsExtensionDependencies.some(values);
    }

    private record ConfiguredClient(
            List<TlsVersionId> supportedVersions
    ) implements TlsExtension.Configured.Client {
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

        }

        @Override
        public Optional<ConfiguredServer> deserialize(TlsContext context, int type, ByteBuffer buffer) {
            var major = readBigEndianInt8(buffer);
            var minor = readBigEndianInt8(buffer);
            var versionId = TlsVersionId.of(major, minor);
            var supportedVersions = context.getNegotiatedValue(TlsProperty.version())
                    .stream()
                    .collect(Collectors.toUnmodifiableMap(TlsVersion::id, Function.identity()));
            var supportedVersion = supportedVersions.get(versionId);
            if(supportedVersion == null) {
                throw new TlsAlert("Remote tried to negotiate a version that wasn't advertised");
            }
            var extension = new ConfiguredServer(supportedVersion);
            return Optional.of(extension);
        }

        @Override
        public int payloadLength() {
            return INT8_LENGTH + INT16_LENGTH * supportedVersions.size();
        }

        @Override
        public int type() {
            return SUPPORTED_VERSIONS_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return SUPPORTED_VERSIONS_VERSIONS;
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.none();
        }
    }

    private record ConfiguredServer(
            TlsVersion version
    ) implements TlsExtension.Configured.Server {
        @Override
        public void serializePayload(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, version.id().major());
            writeBigEndianInt8(buffer, version.id().minor());
        }

        @Override
        public int payloadLength() {
            return INT16_LENGTH;
        }

        @Override
        public int type() {
            return SUPPORTED_VERSIONS_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return SUPPORTED_VERSIONS_VERSIONS;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            context.addNegotiatedProperty(TlsProperty.version(), version);
        }

        @Override
        public Optional<ConfiguredClient> deserialize(TlsContext context, int type, ByteBuffer buffer) {
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
            var extension = new ConfiguredClient(versions);
            return Optional.of(extension);
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.none();
        }
    }
}
