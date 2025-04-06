package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.certificate.TlsCertificateChainType;
import it.auties.leap.tls.certificate.TlsCertificateURLAndHash;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public record CertificateURLMessage(
        TlsVersion version,
        TlsSource source,
        TlsCertificateChainType type,
        List<TlsCertificateURLAndHash> urlAndHashList,
        int urlAndHashListLength
) implements TlsHandshakeMessage {
    private static final byte ID = 0x15;
    private static final TlsMessageDeserializer DESERIALIZER = new TlsMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var typeId = readBigEndianInt8(buffer);
            var type = TlsCertificateChainType.of(typeId)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid certificate chain type: " + typeId));
            var urlAndHashList = new ArrayList<TlsCertificateURLAndHash>();
            var urlAndHashListLength = buffer.remaining() >= INT16_LENGTH ? readBigEndianInt16(buffer) : 0;
            try (var _ = scopedRead(buffer, urlAndHashListLength)) {
                while (buffer.hasRemaining()) {
                    var urlAndHash = TlsCertificateURLAndHash.of(buffer);
                    urlAndHashList.add(urlAndHash);
                }
            }
            return new CertificateURLMessage(metadata.version(), metadata.source(), type, urlAndHashList, urlAndHashListLength);
        }
    };

    public static TlsMessageDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public TlsMessageContentType contentType() {
        return TlsMessageContentType.HANDSHAKE;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, type.id());
        if(urlAndHashListLength > 0) {
            writeBigEndianInt16(buffer, urlAndHashListLength);
            for(var urlAndHash : urlAndHashList) {
                urlAndHash.serialize(buffer);
            }
        }
    }

    @Override
    public int payloadLength() {
        return INT8_LENGTH
                + (urlAndHashListLength > 0 ? INT16_LENGTH + urlAndHashListLength : 0);
    }


    @Override
    public void apply(TlsContext context) {

    }
}
