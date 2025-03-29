package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

// TODO
//   struct {
//          ContentType type;       /* same as TLSPlaintext.type */
//          ProtocolVersion version;/* same as TLSPlaintext.version */
//          uint16 length;
//          opaque fragment[TLSCompressed.length];
//      } TLSCompressed;
//   length
//      The length (in bytes) of the following TLSCompressed.fragment.
//      The length MUST NOT exceed 2^14 + 1024.
//      How to handle serialization and deserialization?
public interface TlsMessage {
    byte id();
    TlsVersion version();
    TlsSource source();
    TlsMessageContentType contentType();
    void serializePayload(ByteBuffer buffer);
    int payloadLength();
    void apply(TlsContext context);

    default void serializeWithRecord(ByteBuffer payload) {
        var payloadLength = payloadLength();
        try(var _ = scopedWrite(payload, recordLength() + payloadLength, true)) {
            writeBigEndianInt8(payload, contentType().id());
            version().serialize(payload);
            writeBigEndianInt16(payload, payloadLength);
            serializePayload(payload);
        }
    }

    default void serialize(ByteBuffer payload) {
        try(var _ = scopedWrite(payload, payloadLength(), true)) {
            serializePayload(payload);
        }
    }

    default int length() {
        return recordLength() + payloadLength();
    }

    static int recordLength() {
        return INT8_LENGTH      // contentType
                + INT16_LENGTH  // version
                + INT16_LENGTH; // payloadLength
    }
}
