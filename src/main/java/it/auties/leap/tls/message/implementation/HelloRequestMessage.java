package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.net.URI;
import java.nio.ByteBuffer;

public record HelloRequestMessage(
        TlsVersion version,
        TlsSource source
) implements TlsHandshakeMessage {
    private static final byte ID = 0x00;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            if(buffer.hasRemaining()) {
                throw new TlsAlert(
                        "Expected server hello request message to have an empty payload",
                        URI.create("https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.9"),
                        "7.4.1.1",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.INTERNAL_ERROR
                );
            }

            return new HelloRequestMessage(metadata.version(), metadata.source());
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

    }

    @Override
    public int payloadLength() {
        return 0;
    }


    @Override
    public void apply(TlsContext context) {

    }
}
