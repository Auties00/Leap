package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDecoder;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class ExtendedMasterSecretExtension implements TlsExtension.Concrete {
    private static final ExtendedMasterSecretExtension INSTANCE = new ExtendedMasterSecretExtension();

    private static final TlsExtensionDecoder DECODER = new TlsExtensionDecoder() {
        @Override
        public Optional<? extends Concrete> decode(ByteBuffer buffer, int type, TlsEngine.Mode mode) {
            if(buffer.hasRemaining()) {
                throw new IllegalArgumentException("Unexpected extension payload");
            }

            return Optional.of(ExtendedMasterSecretExtension.instance());
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsEngine.Mode mode) {
            return ExtendedMasterSecretExtension.class;
        }
    };

    private ExtendedMasterSecretExtension() {

    }

    public static ExtendedMasterSecretExtension instance() {
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
        return EXTENDED_MASTER_SECRET_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return EXTENDED_MASTER_SECRET_VERSIONS;
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
        return "ExtendedMasterSecretExtension[]";
    }
}
