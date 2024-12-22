package it.auties.leap.tls.message.server;

import it.auties.leap.tls.util.BufferHelper;
import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferHelper.writeBytes;

public final class ServerFinishedMessage extends TlsHandshakeMessage {
    public static final int ID = 0x14;

    private final byte[] hash;
    public ServerFinishedMessage(TlsVersion tlsVersion, TlsSource source, byte[] hash) {
        super(tlsVersion, source);
        if(hash == null || hash.length < MIN_HASH_LENGTH) {
            throw new TlsException("The hash should be at least %s bytes long".formatted(MIN_HASH_LENGTH));
        }

        this.hash = hash;
    }

    public static ServerFinishedMessage of(TlsVersion tlsVersion, TlsSource source, ByteBuffer buffer) {
        var hash = BufferHelper.readBytes(buffer, buffer.remaining());
        return new ServerFinishedMessage(tlsVersion, source, hash);
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
