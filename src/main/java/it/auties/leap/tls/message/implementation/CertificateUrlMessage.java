package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificateUrl;
import it.auties.leap.tls.certificate.TlsCertificateUrlAndHash;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public record CertificateUrlMessage(
        TlsVersion version,
        TlsSource source,
        TlsCertificateUrl.IdentifierType type,
        List<TlsCertificateUrlAndHash> urlAndHashList,
        int urlAndHashListLength
) implements TlsHandshakeMessage {
    private static final byte ID = 0x15;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var typeId = readBigEndianInt8(buffer);
            var type = TlsCertificateUrl.IdentifierType.of(typeId).orElseThrow(() -> new TlsAlert(
                    "Cannot decode CertificateUrlMessage: unknown type " + typeId,
                    TlsAlertLevel.FATAL,
                    TlsAlertType.DECODE_ERROR
            ));
            var urlAndHashList = new ArrayList<TlsCertificateUrlAndHash>();
            var urlAndHashListLength = buffer.remaining() >= INT16_LENGTH ? readBigEndianInt16(buffer) : 0;
            try (var _ = scopedRead(buffer, urlAndHashListLength)) {
                while (buffer.hasRemaining()) {
                    var urlAndHash = TlsCertificateUrlAndHash.of(buffer);
                    urlAndHashList.add(urlAndHash);
                }
            }
            return new CertificateUrlMessage(metadata.version(), metadata.source(), type, urlAndHashList, urlAndHashListLength);
        }
    };

    public static TlsHandshakeMessageDeserializer deserializer() {
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

    @Override
    public boolean hashable() {
        return true;
    }

    public void validate(TlsContext context) {

    }
}
