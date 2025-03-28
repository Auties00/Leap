package it.auties.leap.tls.extension.implementation.sni;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.name.TlsNameType;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

final class SNIExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new SNIExtensionDeserializer();

    private SNIExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var listLength = readBigEndianInt16(buffer);
        if(listLength == 0) {
            return Optional.empty();
        }

        try(var _ = scopedRead(buffer, listLength)) {
            var nameTypeId = readBigEndianInt8(buffer);
            var nameType = TlsNameType.of(nameTypeId);
            if(nameType.isEmpty()) {
                return Optional.empty();
            }

            var nameBytes = readBytesBigEndian16(buffer);
            // TODO: Check if name matches local
            var extension = new SNIExtension(nameBytes, nameType.get());
            return Optional.of(extension);
        }
    }
}
