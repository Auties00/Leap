package it.auties.leap.tls.extension.implementation.keyShare;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt16;
import static it.auties.leap.tls.util.BufferUtils.readBytesBigEndian16;

final class KeyShareExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new KeyShareExtensionDeserializer();

    private KeyShareExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var entries = new ArrayList<KeyShareEntry>();
        var entriesSize = buffer.remaining();
        while (buffer.hasRemaining()) {
            var namedGroupId = readBigEndianInt16(buffer);
            var publicKey = readBytesBigEndian16(buffer);
            var entry = new KeyShareEntry(namedGroupId, publicKey);
            entries.add(entry);
        }
        var extension = new KeyShareExtension(entries, entriesSize);
        return Optional.of(extension);
    }
}
