package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.TlsGREASE;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class SupportedVersionsExtension {
    private static final TlsExtensionDeserializer DECODER = (context, source, _, buffer) -> {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        if(mode == TlsContextMode.CLIENT && source == TlsSource.LOCAL || mode == TlsContextMode.SERVER && source == TlsSource.REMOTE) {
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
            var extension = new Client.Concrete(versions);
            return Optional.of(extension);
        }else {
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

            var extension = new Server(supportedVersion);
            return Optional.of(extension);
        }
    };

    public static TlsConfigurableExtension instance() {
        return Client.Configurable.INSTANCE;
    }

    public static TlsExtension of(List<TlsVersionId> tlsVersions) {
        return new Client.Concrete(tlsVersions);
    }

    private static abstract sealed class Client extends SupportedVersionsExtension {
        public static final class Concrete extends Client implements TlsConcreteExtension {
            private final List<TlsVersionId> versions;

            public Concrete(List<TlsVersionId> versions) {
                this.versions = versions;
            }

            @Override
            public void serializePayload(ByteBuffer buffer) {
                var payloadSize = versions.size() * INT16_LENGTH;
                writeBigEndianInt8(buffer, payloadSize);
                for (var tlsVersion : versions) {
                    writeBigEndianInt8(buffer, tlsVersion.major());
                    writeBigEndianInt8(buffer, tlsVersion.minor());
                }
            }

            @Override
            public void apply(TlsContext context, TlsSource source) {

            }

            @Override
            public int payloadLength() {
                return INT8_LENGTH + INT16_LENGTH * versions.size();
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
            public TlsExtensionDeserializer decoder() {
                return DECODER;
            }

            @Override
            public boolean equals(Object o) {
                return o instanceof Concrete concrete
                        && Objects.equals(versions, concrete.versions);
            }

            @Override
            public int hashCode() {
                return Objects.hashCode(versions);
            }

            @Override
            public String toString() {
                return "SupportedVersionsExtension[" +
                        "versions=" + versions + ']';
            }
        }

        public static final class Configurable extends SupportedVersionsExtension implements TlsConfigurableExtension {
            private static final TlsConfigurableExtension INSTANCE = new Client.Configurable();

            private Configurable() {

            }

            @Override
            public Optional<? extends TlsConcreteExtension> newInstance(TlsContext context, int messageLength) {
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
                return Optional.of(new Client.Concrete(supportedVersions));
            }

            @Override
            public TlsExtensionDependencies dependencies() {
                var values = TlsGREASE.values()
                        .stream()
                        .map(grease -> grease.versionId().value())
                        .toArray(Integer[]::new);
                return TlsExtensionDependencies.some(values);
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
            public TlsExtensionDeserializer decoder() {
                return DECODER;
            }

            @Override
            public String toString() {
                return "SupportedVersionsExtension[versions=configurable]";
            }
        }
    }

    private static final class Server extends SupportedVersionsExtension implements TlsConcreteExtension {
        private final TlsVersion version;

        private Server(TlsVersion version) {
            this.version = version;
        }

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
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            if (source == TlsSource.REMOTE) {
                context.addNegotiatedProperty(TlsProperty.version(), version);
            }
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Server server
                    && Objects.equals(version, server.version);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(version);
        }

        @Override
        public String toString() {
            return "SupportedVersionsExtension[" +
                    "version=" + version + ']';
        }
    }
}
