package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;;

public sealed abstract class FinishedMessage extends TlsHandshakeMessage {
    private static final int MIN_HASH_LENGTH = 12;

    FinishedMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Server extends FinishedMessage {
        public static final int ID = 0x14;

        private final byte[] hash;
        public Server(TlsVersion tlsVersion, TlsSource source, byte[] hash) {
            super(tlsVersion, source);
            if(hash == null || hash.length < MIN_HASH_LENGTH) {
                throw new TlsException("The hash should be at least %s bytes long".formatted(MIN_HASH_LENGTH));
            }

            this.hash = hash;
        }

        public static Server of(TlsContext ignoredEngine, ByteBuffer buffer, Metadata metadata) {
            var hash = readBytes(buffer, buffer.remaining());
            return new Server(metadata.version(), metadata.source(), hash);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public Type type() {
            return Type.SERVER_FINISHED;
        }

        @Override
        public ContentType contentType() {
            return ContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {
            writeBytes(buffer, hash);
        }

        @Override
        public int handshakePayloadLength() {
            return hash.length;
        }
    }

    public static final class Client extends FinishedMessage {
        public static final int ID = 0x14;

        private final byte[] hash;
        public Client(TlsVersion tlsVersion, TlsSource source, byte[] hash) {
            super(tlsVersion, source);
            if(hash == null || hash.length < MIN_HASH_LENGTH) {
                throw new TlsException("The hash should be at least %s bytes long".formatted(MIN_HASH_LENGTH));
            }

            this.hash = hash;
        }

        public static Client of(TlsContext ignoredEngine, ByteBuffer buffer, Metadata metadata) {
            var hash = readBytes(buffer, buffer.remaining());
            return new Client(metadata.version(), metadata.source(), hash);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public Type type() {
            return Type.CLIENT_FINISHED;
        }

        @Override
        public ContentType contentType() {
            return ContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {
            writeBytes(buffer, hash);
        }

        @Override
        public int handshakePayloadLength() {
            return hash.length;
        }
    }
}
