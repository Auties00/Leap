package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt16;

non-sealed public interface TlsConcreteExtension extends TlsExtension {
    default void serializeExtension(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, extensionType());
        writeBigEndianInt16(buffer, extensionPayloadLength());
        serializeExtensionPayload(buffer);
    }

    default int extensionLength() {
        return extensionHeaderLength() + extensionPayloadLength();
    }

    void serializeExtensionPayload(ByteBuffer buffer);

    int extensionPayloadLength();

    void apply(TlsContext context, TlsSource source);
}
