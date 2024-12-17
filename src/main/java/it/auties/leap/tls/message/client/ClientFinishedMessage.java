package it.auties.leap.tls.message.client;

import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.BufferHelper;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.BufferHelper.writeBytes;

public final class ClientFinishedMessage extends TlsHandshakeMessage {
    public static final int ID = 0x14;

    private final byte[] hash;
    public ClientFinishedMessage(TlsVersion tlsVersion, Source source, byte[] hash) {
        super(tlsVersion, source);
        if(hash == null || hash.length < MIN_HASH_LENGTH) {
            throw new TlsException("The hash should be at least %s bytes long".formatted(MIN_HASH_LENGTH));
        }

        this.hash = hash;
    }

    public static ClientFinishedMessage of(TlsVersion tlsVersion, Source source, ByteBuffer buffer) {
        var hash = BufferHelper.readBytes(buffer, buffer.remaining());
        return new ClientFinishedMessage(tlsVersion, source, hash);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsMode mode, Source source, List<Type> precedingMessages) {
        if(precedingMessages.isEmpty()) {
            return false;
        }

        var expectedMessage = version == TlsVersion.TLS13 || version == TlsVersion.DTLS13 ? Type.CLIENT_HELLO : Type.CLIENT_CHANGE_CIPHER_SPEC;
        if(precedingMessages.getLast() != expectedMessage) {
            return false;
        }

        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsMode.CLIENT;
                case REMOTE -> mode == TlsMode.SERVER;
            };
            case UDP -> false;
        };
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
