package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.message.TlsMessageType;
import it.auties.leap.tls.version.TlsVersion;

import java.net.URI;
import java.nio.ByteBuffer;

public sealed abstract class HelloRequestMessage extends TlsHandshakeMessage{
    HelloRequestMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Server extends HelloRequestMessage {
        public static final byte ID = 0x00;

        public Server(TlsVersion tlsVersion, TlsSource source) {
            super(tlsVersion, source);
        }

        public static Server of(TlsContext ignoredEngine, ByteBuffer buffer, TlsMessageMetadata metadata) {
            if(buffer.hasRemaining()) {
                throw new TlsException("Expected server hello request message to have an empty payload", URI.create("https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.9"), "7.4.1.1");
            }

            return new Server(metadata.version(), metadata.source());
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public TlsMessageType type() {
            return TlsMessageType.SERVER_HELLO_REQUEST;
        }

        @Override
        public TlsMessageContentType contentType() {
            return TlsMessageContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {

        }

        @Override
        public int handshakePayloadLength() {
            return 0;
        }
    }
}
