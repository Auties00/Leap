package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt16;

non-sealed public interface TlsConcreteExtension extends TlsExtension {
    default void serialize(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, extensionType());
        writeBigEndianInt16(buffer, payloadLength());
        serializePayload(buffer);
    }

    default int length() {
        return extensionHeaderLength() + payloadLength();
    }

    void serializePayload(ByteBuffer buffer);

    int payloadLength();

    void apply(TlsContext context, TlsSource source);
}
