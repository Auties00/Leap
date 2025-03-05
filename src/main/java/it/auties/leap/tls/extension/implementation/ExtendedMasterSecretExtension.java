package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class ExtendedMasterSecretExtension {
    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer() {
        @Override
        public Optional<? extends TlsExtension.Concrete> deserialize(ByteBuffer buffer, TlsSource source, TlsMode mode, int type) {
            if(buffer.hasRemaining()) {
                throw new IllegalArgumentException("Unexpected extension payload");
            }

            return Optional.of(ExtendedMasterSecretExtension.Concrete.instance());
        }

        @Override
        public Class<? extends TlsExtension.Concrete> toConcreteType(TlsSource source, TlsMode mode) {
            return ExtendedMasterSecretExtension.Concrete.class;
        }
    };


    public static final class Concrete implements TlsExtension.Concrete {
        private static final ExtendedMasterSecretExtension.Concrete INSTANCE = new ExtendedMasterSecretExtension.Concrete();

        private Concrete() {

        }

        public static ExtendedMasterSecretExtension.Concrete instance() {
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
        public TlsExtensionDeserializer decoder() {
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

    public static final class Configurable implements TlsExtension.Configurable {
        private static final ExtendedMasterSecretExtension.Configurable INSTANCE = new ExtendedMasterSecretExtension.Configurable();

        private Configurable() {

        }

        public static ExtendedMasterSecretExtension.Configurable instance() {
            return INSTANCE;
        }

        @Override
        public Optional<? extends Concrete> newInstance(TlsContext context) {
            context.enableExtendedMasterSecret();
            return Optional.of(ExtendedMasterSecretExtension.Concrete.instance());
        }

        @Override
        public Dependencies dependencies() {
            return Dependencies.none();
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
        public TlsExtensionDeserializer decoder() {
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
}