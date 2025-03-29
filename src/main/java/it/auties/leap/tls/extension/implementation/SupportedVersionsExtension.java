package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.TlsGREASE;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.*;
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

public final class SupportedVersionsExtension implements TlsConfigurableClientExtension {
    private static final TlsExtensionDeserializer DESERIALIZER = (context, _, buffer) -> {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        return switch (mode) {
            case CLIENT -> {
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
                yield Optional.of(extension);
            }

            case SERVER -> {
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
                yield Optional.of(extension);
            }
        };
    };

    private static final SupportedVersionsExtension INSTANCE = new SupportedVersionsExtension();

    private SupportedVersionsExtension() {

    }

    public static SupportedVersionsExtension instance() {
        return INSTANCE;
    }

    @Override
    public int extensionType() {
        return SUPPORTED_VERSIONS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SUPPORTED_VERSIONS_VERSIONS;
    }

    @Override
    public Optional<? extends TlsConfiguredExtension> configure(TlsContext context, int messageLength) {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        return switch (mode) {
            case CLIENT -> {
                var supportedVersions = new ArrayList<TlsVersionId>();
                context.getNegotiableValue(TlsProperty.version())
                        .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()))
                        .forEach(version -> supportedVersions.add(version.id()));
                var grease = context.getNegotiableValue(TlsProperty.extensions())
                        .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.extensions()))
                        .stream()
                        .anyMatch(entry -> TlsGREASE.isGrease(entry.extensionType()));
                if (grease) {
                    supportedVersions.add(TlsGREASE.greaseRandom());
                }
                yield Optional.of(new ConfiguredClient(supportedVersions));
            }
            case SERVER -> {
                var version = context.getNegotiableValue(TlsProperty.version())
                        .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()))
                        .stream()
                        .reduce((first, second) -> first.id().value() > second.id().value() ? first : second)
                        .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()));
                yield Optional.of(new ConfiguredServer(version));
            }
        };
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
    ) implements TlsConfiguredClientExtension {
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
        public int payloadLength() {
            return INT8_LENGTH + INT16_LENGTH * supportedVersions.size();
        }

        @Override
        public int extensionType() {
            return SUPPORTED_VERSIONS_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return SUPPORTED_VERSIONS_VERSIONS;
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

    private record ConfiguredServer(
            TlsVersion version
    ) implements TlsConfiguredServerExtension {
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
        public int extensionType() {
            return SUPPORTED_VERSIONS_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return SUPPORTED_VERSIONS_VERSIONS;
        }

        @Override
        public TlsExtensionDeserializer deserializer() {
            return DESERIALIZER;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            context.addNegotiatedProperty(TlsProperty.version(), version);
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.none();
        }
    }
}
