package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsMode;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.cipher.TlsGREASE;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.extension.TlsConfigurableExtension;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class SupportedVersionsExtension {
    private static final TlsExtensionDeserializer DECODER = (context, source, _, buffer) -> {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        if(mode == TlsMode.CLIENT && source == TlsSource.LOCAL || mode == TlsMode.SERVER && source == TlsSource.REMOTE) {
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
            var extension = new Server(versionId);
            return Optional.of(extension);
        }
    };

    public static abstract sealed class Client extends SupportedVersionsExtension {
        public static final class Concrete extends Client implements TlsConcreteExtension {
            private final List<TlsVersionId> tlsVersions;
            public Concrete(List<TlsVersionId> tlsVersions) {
                this.tlsVersions = tlsVersions;
            }

            @Override
            public void serializeExtensionPayload(ByteBuffer buffer) {
                var payloadSize = tlsVersions.size() * INT16_LENGTH;
                writeBigEndianInt8(buffer, payloadSize);
                for (var tlsVersion : tlsVersions) {
                    writeBigEndianInt8(buffer, tlsVersion.major());
                    writeBigEndianInt8(buffer, tlsVersion.minor());
                }
            }

            @Override
            public int extensionPayloadLength() {
                return INT8_LENGTH + INT16_LENGTH * tlsVersions.size();
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
            public boolean equals(Object obj) {
                if (obj == this) return true;
                if (obj == null || obj.getClass() != this.getClass()) return false;
                var that = (Client.Concrete) obj;
                return Objects.equals(this.tlsVersions, that.tlsVersions);
            }

            @Override
            public int hashCode() {
                return Objects.hash(tlsVersions);
            }

            @Override
            public String toString() {
                return "SupportedVersionsExtension[" +
                        "versions=" + tlsVersions + ']';
            }
        }

        public static final class Configurable extends SupportedVersionsExtension implements TlsConfigurableExtension {
            private static final TlsConfigurableExtension INSTANCE = new Client.Configurable();
            public static final TlsExtensionDependencies DEPENDENCIES = TlsExtensionDependencies.some(GREASEExtension.greaseValues()
                    .stream()
                    .map(GREASEExtension::extensionType)
                    .toArray(Integer[]::new));

            private Configurable() {

            }

            public static TlsConfigurableExtension instance() {
                return INSTANCE;
            }

            @Override
            public Optional<? extends TlsConcreteExtension> newInstance(TlsContext context, int messageLength) {
                var supportedVersions = new ArrayList<TlsVersionId>();
                for (var tlsVersion : context.negotiableVersions()) {
                    supportedVersions.add(tlsVersion.id());
                }

                if (context.processedExtensions().stream().anyMatch(entry -> TlsGREASE.isGrease(entry.extensionType()))) {
                    supportedVersions.add(TlsGREASE.greaseRandom());
                }

                return Optional.of(new Client.Concrete(supportedVersions));
            }

            @Override
            public TlsExtensionDependencies dependencies() {
                return DEPENDENCIES;
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
        public void serializeExtensionPayload(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, version.id().major());
            writeBigEndianInt8(buffer, version.id().minor());
        }

        @Override
        public int extensionPayloadLength() {
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
