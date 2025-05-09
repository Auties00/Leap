package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt16;

public interface TlsExtensionPayload {
    int type();
    void serializePayload(ByteBuffer buffer);
    int payloadLength();
    void apply(TlsContext context, TlsSource source);

    default void serialize(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, type());
        writeBigEndianInt16(buffer, payloadLength());
        serializePayload(buffer);
    }

    default int length() {
        return INT16_LENGTH
                + INT16_LENGTH
                + payloadLength();
    }
}
