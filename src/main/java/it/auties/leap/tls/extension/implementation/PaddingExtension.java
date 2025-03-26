package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt8;

public sealed abstract class PaddingExtension {
    private static final TlsExtensionDeserializer DECODER = (_, _, _, buffer) -> {
        var padding = readBigEndianInt8(buffer);
        var extension = new Concrete(padding);
        return Optional.of(extension);
    };

    public static TlsExtension of(int targetLength) {
        return new Configurable(targetLength);
    }

    private static final class Concrete extends PaddingExtension implements TlsConcreteExtension {
        private final int length;

        private Concrete(int length) {
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
        public void apply(TlsContext context, TlsSource source) {

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

        @Override
        public boolean equals(Object obj) {
            return obj instanceof PaddingExtension.Concrete that
                    && this.length == that.length;
        }

        @Override
        public int hashCode() {
            return Objects.hash(length);
        }
    }

    public static final class Configurable extends PaddingExtension implements TlsConfigurableExtension {
        private final int targetLength;

        private Configurable(int targetLength) {
            this.targetLength = targetLength;
        }

        @Override
        public Optional<? extends TlsConcreteExtension> newInstance(TlsContext context, int messageLength) {
            var actualLength = messageLength + extensionHeaderLength();
            if (actualLength > targetLength) {
                return Optional.empty();
            }

            var result = new PaddingExtension.Concrete(targetLength - actualLength);
            return Optional.of(result);
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.all();
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
        public boolean equals(Object obj) {
            return obj instanceof PaddingExtension.Configurable that
                    && this.targetLength == that.targetLength;
        }

        @Override
        public int hashCode() {
            return Objects.hash(targetLength);
        }

        @Override
        public String toString() {
            return "PaddingExtension[" +
                    "length=<configurable>" +
                    ']';
        }
    }
}
