package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.cipher.TlsGREASE;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtension.Concrete;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class SupportedVersionsExtension {
    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer() {
        @Override
        public Optional<? extends Concrete> deserialize(ByteBuffer buffer, TlsSource source, TlsMode mode, int type) {
            return switch (mode) {
                case CLIENT -> {
                    var major = readBigEndianInt8(buffer);
                    var minor = readBigEndianInt8(buffer);
                    var versionId = TlsVersionId.of(major, minor);
                    yield Optional.of(new Server(versionId));
                }
                case SERVER -> {
                    var payloadSize = readBigEndianInt8(buffer);
                    var versions = new ArrayList<TlsVersionId>();
                    try (var _ = scopedRead(buffer, payloadSize)) {
                        var versionsSize = payloadSize / INT16_LENGTH;
                        for (var i = 0; i < versionsSize; i++) {
                            var versionId = TlsVersionId.of(readBigEndianInt8(buffer), readBigEndianInt8(buffer));
                            versions.add(versionId);
                        }
                    }
                    yield Optional.of(new Client.Concrete(versions));
                }
            };
        }

    };

    public static final class Server extends SupportedVersionsExtension implements Concrete {
        private final TlsVersionId tlsVersion;

        public Server(TlsVersionId tlsVersion) {
            this.tlsVersion = tlsVersion;
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, tlsVersion.major());
            writeBigEndianInt8(buffer, tlsVersion.minor());
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

        public TlsVersionId tlsVersion() {
            return tlsVersion;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (Server) obj;
            return Objects.equals(this.tlsVersion, that.tlsVersion);
        }

        @Override
        public int hashCode() {
            return Objects.hash(tlsVersion);
        }

        @Override
        public String toString() {
            return "SupportedVersionsExtension[" +
                    "tlsVersion=" + tlsVersion + ']';
        }
    }

    public static abstract sealed class Client extends SupportedVersionsExtension {
        public static final class Concrete extends Client implements TlsExtension.Concrete  {
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

            public List<TlsVersionId> tlsVersions() {
                return tlsVersions;
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
                        "tlsVersions=" + tlsVersions + ']';
            }
        }

        public static final class Configurable extends SupportedVersionsExtension implements TlsExtension.Configurable {
            private static final Configurable INSTANCE = new Client.Configurable();
            public static final Dependencies DEPENDENCIES = Dependencies.some(GREASEExtension.greaseValues()
                    .stream()
                    .map(GREASEExtension::extensionType)
                    .toArray(Integer[]::new));

            private Configurable() {

            }

            public static Configurable instance() {
                return INSTANCE;
            }

            @Override
            public Optional<? extends Concrete> newInstance(TlsContext context) {
                var supportedVersions = new ArrayList<TlsVersionId>();
                var chosenVersion = context.config().version();
                switch (chosenVersion) {
                    case TLS13 -> {
                        supportedVersions.add(TlsVersion.TLS13.id());
                        supportedVersions.add(TlsVersion.TLS12.id());
                    }
                    case DTLS13 -> {
                        supportedVersions.add(TlsVersion.DTLS13.id());
                        supportedVersions.add(TlsVersion.DTLS12.id());
                    }
                    default -> supportedVersions.add(chosenVersion.id());
                }

                if (context.hasExtension(TlsGREASE::isGrease)) {
                    supportedVersions.add(TlsGREASE.greaseRandom());
                }

                return Optional.of(new Client.Concrete(supportedVersions));
            }

            @Override
            public Dependencies dependencies() {
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
                return "SupportedVersionsExtension[tlsVersions=configurable]";
            }
        }
    }
}
