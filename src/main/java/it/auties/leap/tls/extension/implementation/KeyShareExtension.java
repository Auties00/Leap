package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.TlsMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDecoder;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class KeyShareExtension {
    private static final TlsExtensionDecoder DECODER = new TlsExtensionDecoder() {
        @Override
        public Optional<? extends TlsExtension.Concrete> decode(ByteBuffer buffer, int type, TlsMode mode) {
            var namedGroupId = readLittleEndianInt16(buffer);
            var publicKey = readBytesLittleEndian16(buffer);
            var extension = new Concrete(publicKey, namedGroupId);
            return Optional.of(extension);
        }

        @Override
        public Class<? extends TlsExtension.Concrete> toConcreteType(TlsMode mode) {
            return Concrete.class;
        }
    };

    public static final class Concrete extends KeyShareExtension implements TlsExtension.Concrete {
        private final byte[] publicKey;
        private final int namedGroup;

        public Concrete(byte[] publicKey, int namedGroup) {
            this.publicKey = publicKey;
            this.namedGroup = namedGroup;
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {
            var size = INT16_LENGTH + INT16_LENGTH + publicKey.length;
            writeLittleEndianInt16(buffer, size);
            writeLittleEndianInt16(buffer, namedGroup);
            writeBytesLittleEndian16(buffer, publicKey);
        }

        @Override
        public int extensionPayloadLength() {
            return INT16_LENGTH + INT16_LENGTH + INT16_LENGTH + publicKey.length;
        }

        @Override
        public int extensionType() {
            return KEY_SHARE_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return KEY_SHARE_VERSIONS;
        }

        @Override
        public TlsExtensionDecoder decoder() {
            return DECODER;
        }

        public byte[] publicKey() {
            return publicKey;
        }

        public int namedGroup() {
            return namedGroup;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (KeyShareExtension.Concrete) obj;
            return Arrays.equals(this.publicKey, that.publicKey) &&
                    this.namedGroup == that.namedGroup;
        }

        @Override
        public int hashCode() {
            return Objects.hash(Arrays.hashCode(publicKey), namedGroup);
        }

        @Override
        public String toString() {
            return "Concrete[" +
                    "publicKey=" + Arrays.toString(publicKey) + ", " +
                    "namedGroup=" + namedGroup + ']';
        }
    }

    public static final class Configurable extends KeyShareExtension implements TlsExtension.Configurable {
        private static final KeyShareExtension.Configurable INSTANCE = new KeyShareExtension.Configurable();

        private Configurable() {

        }

        public static TlsExtension instance() {
            return INSTANCE;
        }

        @Override
        public Optional<? extends TlsExtension.Concrete> newInstance(TlsEngine engine) {
            var publicKey = engine.localKeyPair()
                    .map(e -> e.getPublic().getEncoded())
                    .orElse(null);
            if (publicKey == null) {
                return Optional.empty();
            }

            var result = new KeyShareExtension.Concrete(publicKey, 1);
            return Optional.of(result);
        }

        @Override
        public Dependencies dependencies() {
            return Dependencies.some(SupportedGroupsExtension.class);
        }

        @Override
        public int extensionType() {
            return KEY_SHARE_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return KEY_SHARE_VERSIONS;
        }

        @Override
        public TlsExtensionDecoder decoder() {
            return DECODER;
        }
    }
}
