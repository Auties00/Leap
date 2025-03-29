package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt16;

public sealed interface TlsConfiguredExtension extends TlsExtensionState permits TlsConfiguredClientExtension, TlsConfiguredServerExtension {
    default void serialize(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, extensionType());
        writeBigEndianInt16(buffer, payloadLength());
        serializePayload(buffer);
    }

    default int extensionHeaderLength() {
        return INT16_LENGTH + INT16_LENGTH;
    }

    default int length() {
        return extensionHeaderLength() + payloadLength();
    }

    void serializePayload(ByteBuffer buffer);
    int payloadLength();
    void apply(TlsContext context, TlsSource source);
}
