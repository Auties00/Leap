package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtension.Concrete;
import it.auties.leap.tls.extension.TlsExtensionDecoder;
import it.auties.leap.tls.cipher.TlsGREASE;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class SupportedVersionsExtension {
    private static final TlsExtensionDecoder DECODER = new TlsExtensionDecoder() {
        @Override
        public Optional<? extends Concrete> decode(ByteBuffer buffer, int type, TlsEngine.Mode mode) {
            return switch (mode) {
                case CLIENT -> {
                    var payloadSize = readLittleEndianInt8(buffer);
                    var versions = new ArrayList<TlsVersionId>();
                    try (var _ = scopedRead(buffer, payloadSize)) {
                        var versionsSize = payloadSize / INT16_LENGTH;
                        for (var i = 0; i < versionsSize; i++) {
                            var versionId = TlsVersionId.of(readLittleEndianInt8(buffer), readLittleEndianInt8(buffer));
                            versions.add(versionId);
                        }
                    }
                    yield Optional.of(new Client.Concrete(versions));
                }
                case SERVER -> {
                    var major = readLittleEndianInt8(buffer);
                    var minor = readLittleEndianInt8(buffer);
                    var versionId = TlsVersionId.of(major, minor);
                    yield Optional.of(new Server(versionId));
                }
            };
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsEngine.Mode mode) {
            return switch (mode) {
                case CLIENT -> Client.Concrete.class;
                case SERVER -> Server.class;
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
            writeLittleEndianInt8(buffer, tlsVersion.major());
            writeLittleEndianInt8(buffer, tlsVersion.minor());
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
        public TlsExtensionDecoder decoder() {
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
                writeLittleEndianInt8(buffer, payloadSize);
                for (var tlsVersion : tlsVersions) {
                    writeLittleEndianInt8(buffer, tlsVersion.major());
                    writeLittleEndianInt8(buffer, tlsVersion.minor());
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
            public TlsExtensionDecoder decoder() {
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

            private Configurable() {

            }

            public static Configurable instance() {
                return INSTANCE;
            }

            @Override
            public Optional<? extends Concrete> newInstance(TlsEngine engine) {
                var supportedVersions = new ArrayList<TlsVersionId>();
                var chosenVersion = engine.config().version();
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

                if (engine.hasExtension(TlsGREASE::isGrease)) {
                    supportedVersions.add(randomGrease());
                }

                return Optional.of(new Client.Concrete(supportedVersions));
            }

            private static TlsVersionId randomGrease() {
                var random = new SecureRandom();
                var values = TlsGREASE.values();
                var index = random.nextInt(0, values.size());
                return values.get(index)
                        .versionId();
            }

            @Override
            public Dependencies dependencies() {
                return Dependencies.some(GREASEExtension.class);
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
            public TlsExtensionDecoder decoder() {
                return DECODER;
            }

            @Override
            public String toString() {
                return "SupportedVersionsExtension[tlsVersions=configurable]";
            }
        }
    }
}
