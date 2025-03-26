package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class KeyShareExtension {
    private static final TlsExtensionDeserializer DECODER = (_, _, _, buffer) -> {
        var entries = new ArrayList<Entry>();
        var entriesSize = buffer.remaining();
        while (buffer.hasRemaining()) {
            var namedGroupId = readBigEndianInt16(buffer);
            var publicKey = readBytesBigEndian16(buffer);
            entries.add(new Entry(namedGroupId, publicKey));
        }
        var extension = new Concrete(entries, entriesSize);
        return Optional.of(extension);
    };

    public static TlsExtension instance() {
        return Configurable.INSTANCE;
    }

    private static final class Concrete extends KeyShareExtension implements TlsConcreteExtension {
        private final List<Entry> entries;
        private final int entriesLength;

        private Concrete(List<Entry> entries, int entriesLength) {
            this.entries = entries;
            this.entriesLength = entriesLength;
        }

        @Override
        public void serializeExtensionPayload(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, entriesLength);
            for(var entry : entries) {
                entry.serialize(buffer);
            }
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {

        }

        @Override
        public int extensionPayloadLength() {
            return INT16_LENGTH + entriesLength;
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
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof KeyShareExtension.Concrete concrete
                    && entriesLength == concrete.entriesLength
                    && Objects.equals(entries, concrete.entries);
        }

        @Override
        public int hashCode() {
            return Objects.hash(entries, entriesLength);
        }

        @Override
        public String toString() {
            return "Concrete[" +
                    "entries=" + entries +
                    ']';
        }
    }

    private static final class Configurable extends KeyShareExtension implements TlsConfigurableExtension {
        private static final KeyShareExtension.Configurable INSTANCE = new KeyShareExtension.Configurable();

        private Configurable() {

        }

        @Override
        public Optional<? extends TlsConcreteExtension> newInstance(TlsContext context, int messageLength) {
            var entries = new ArrayList<Entry>();
            var entriesLength = 0;
            var supportedGroups = context.getNegotiableValue(TlsProperty.supportedGroups())
                    .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.supportedGroups()));
            for(var supportedGroup : supportedGroups) {
                var keyPair = supportedGroup.generateLocalKeyPair(context);
                var publicKey = supportedGroup.dumpPublicKey(keyPair.getPublic());
                var entry = new Entry(supportedGroup.id(), publicKey);
                entries.add(entry);
                entriesLength += entry.length();
            }
            return Optional.of(new KeyShareExtension.Concrete(entries, entriesLength));
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.some(SUPPORTED_GROUPS_TYPE);
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
        public TlsExtensionDeserializer decoder() {
            return DECODER;
        }
    }

    private record Entry(int namedGroup, byte[] publicKey) {
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, namedGroup);
            writeBytesBigEndian16(buffer, publicKey);
        }

        public int length() {
            return INT16_LENGTH + INT16_LENGTH + publicKey.length;
        }
    }
}
