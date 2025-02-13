package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt8;

public sealed abstract class PaddingExtension {
    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer() {
        @Override
        public Optional<? extends TlsExtension.Concrete> deserialize(ByteBuffer buffer, int type, TlsMode mode) {
            var padding = readBigEndianInt8(buffer);
            var extension = new Concrete(padding);
            return Optional.of(extension);
        }

        @Override
        public Class<? extends TlsExtension.Concrete> toConcreteType(TlsMode mode) {
            return Concrete.class;
        }
    };

    public static final class Concrete extends PaddingExtension implements TlsExtension.Concrete {
        private final int length;

        public Concrete(int length) {
            this.length = length;
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {
            for (var j = 0; j < length; j++) {
                buffer.put((byte) 0);
            }
        }

        @Override
        public int extensionPayloadLength() {
            return length;
        }

        @Override
        public int extensionType() {
            return PADDING_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return PADDING_VERSIONS;
        }

        @Override
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }

        @Override
        public String toString() {
            return "PaddingExtension[" +
                    "length=" + length +
                    ']';
        }

        public int length() {
            return length;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (PaddingExtension.Concrete) obj;
            return this.length == that.length;
        }

        @Override
        public int hashCode() {
            return Objects.hash(length);
        }
    }

    public static final class Configurable extends PaddingExtension implements TlsExtension.Configurable {
        private final int targetLength;

        public Configurable(int targetLength) {
            this.targetLength = targetLength;
        }

        @Override
        public Optional<? extends TlsExtension.Concrete> newInstance(TlsContext context) {
            var actualLength = context.processedExtensionsLength() + INT16_LENGTH + INT16_LENGTH;
            if (actualLength > targetLength) {
                return Optional.empty();
            }

            var result = new PaddingExtension.Concrete(targetLength - actualLength);
            return Optional.of(result);
        }

        @Override
        public Dependencies dependencies() {
            return Dependencies.all();
        }

        @Override
        public int extensionType() {
            return PADDING_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return PADDING_VERSIONS;
        }

        @Override
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }

        @Override
        public String toString() {
            return "PaddingExtension[" +
                    "length=configurable" +
                    ']';
        }
    }
}
