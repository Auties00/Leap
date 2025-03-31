package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class KeyShareExtension implements TlsExtension.Configurable {
    private static final KeyShareExtension INSTANCE = new KeyShareExtension();
    
    private KeyShareExtension() {
        
    }

    public static KeyShareExtension instance() {
        return INSTANCE;
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
    public boolean equals(Object o) {
        return o instanceof KeyShareExtension;
    }

    @Override
    public int hashCode() {
        return 1;
    }

    @Override
    public String toString() {
        return "KeyShareExtension[" +
                "entries=" + "<configurable>" +
                ']';
    }

    @Override
    public <T extends TlsExtension.Configured.Agnostic> Optional<? super T> configure(TlsContext context, int messageLength) {
        var entries = new ArrayList<KeyShareEntry>();
        var entriesLength = 0;
        var supportedGroups = context.getNegotiableValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.supportedGroups()));
        for(var supportedGroup : supportedGroups) {
            var keyPair = supportedGroup.generateLocalKeyPair(context);
            var publicKey = supportedGroup.dumpPublicKey(keyPair.getPublic());
            var entry = new KeyShareEntry(supportedGroup.id(), publicKey);
            entries.add(entry);
            entriesLength += entry.length();
        }
        return Optional.of(new Configured(entries, entriesLength));
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.some(SUPPORTED_GROUPS_TYPE);
    }

    private record Configured(
            List<KeyShareEntry> entries,
            int entriesLength
    ) implements TlsExtension.Configured.Agnostic {
        private static final TlsExtensionDeserializer<TlsExtension.Configured.Agnostic> DESERIALIZER = (_, _, buffer) -> {
            var entries = new ArrayList<KeyShareEntry>();
            var entriesSize = buffer.remaining();
            while (buffer.hasRemaining()) {
                var namedGroupId = readBigEndianInt16(buffer);
                var publicKey = readBytesBigEndian16(buffer);
                var entry = new KeyShareEntry(namedGroupId, publicKey);
                entries.add(entry);
            }
            var extension = new KeyShareExtension.Configured(entries, entriesSize);
            return Optional.of(extension);
        };

        @Override
        public void serializePayload(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, entriesLength);
            for (var entry : entries) {
                entry.serialize(buffer);
            }
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            // TODO: Select client key?
        }

        @Override
        public int payloadLength() {
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
        public TlsExtensionDeserializer<TlsExtension.Configured.Agnostic> responseDeserializer() {
            return DESERIALIZER;
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.none();
        }
    }

    private record KeyShareEntry(
            int namedGroup,
            byte[] publicKey
    ) {
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, namedGroup);
            writeBytesBigEndian16(buffer, publicKey);
        }

        public int length() {
            return INT16_LENGTH + INT16_LENGTH + publicKey.length;
        }
    }
}
