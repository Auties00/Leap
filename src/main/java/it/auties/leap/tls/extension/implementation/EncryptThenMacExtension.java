package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDecoder;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class EncryptThenMacExtension implements TlsExtension.Concrete {
    private static final EncryptThenMacExtension INSTANCE = new EncryptThenMacExtension();

    private static final TlsExtensionDecoder DECODER = new TlsExtensionDecoder() {
        @Override
        public Optional<? extends Concrete> decode(ByteBuffer buffer, int type, TlsMode mode) {
            if (buffer.hasRemaining()) {
                throw new IllegalArgumentException("Unexpected extension payload");
            }

            return Optional.of(EncryptThenMacExtension.instance());
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsMode mode) {
            return EncryptThenMacExtension.class;
        }
    };

    private EncryptThenMacExtension() {

    }

    public static EncryptThenMacExtension instance() {
        return INSTANCE;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {

    }

    @Override
    public int extensionPayloadLength() {
        return 0;
    }

    @Override
    public int extensionType() {
        return ENCRYPT_THEN_MAC_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return ENCRYPT_THEN_MAC_VERSIONS;
    }

    @Override
    public TlsExtensionDecoder decoder() {
        return DECODER;
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this || obj != null && obj.getClass() == this.getClass();
    }

    @Override
    public int hashCode() {
        return 1;
    }

    @Override
    public String toString() {
        return "EncryptThenMacExtension[]";
    }
}
