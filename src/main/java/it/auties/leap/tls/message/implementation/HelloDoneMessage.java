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

public sealed abstract class HelloDoneMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0E;

    HelloDoneMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Server extends HelloDoneMessage {
        public Server(TlsVersion tlsVersion, TlsSource source) {
            super(tlsVersion, source);
        }

        public static Server of(TlsContext ignoredEngine, ByteBuffer buffer, TlsMessageMetadata metadata) {
            if(buffer.hasRemaining()) {
                throw new TlsException("Expected server hello done message to have an empty payload", URI.create("https://datatracker.ietf.org/doc/html/rfc5246"), "7.4.5");
            }

            return new Server(metadata.version(), metadata.source());
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public TlsMessageType type() {
            return TlsMessageType.SERVER_HELLO_DONE;
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
