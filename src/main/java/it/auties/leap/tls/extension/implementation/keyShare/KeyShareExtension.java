package it.auties.leap.tls.extension.implementation.keyShare;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConfiguredClientExtension;
import it.auties.leap.tls.extension.TlsConfiguredServerExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt16;

record KeyShareExtension(
        List<KeyShareEntry> entries,
        int entriesLength
) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension {
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
    public TlsExtensionDeserializer deserializer() {
        return KeyShareExtensionDeserializer.INSTANCE;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
