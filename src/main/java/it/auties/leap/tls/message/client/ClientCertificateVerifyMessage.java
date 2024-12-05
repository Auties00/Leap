package it.auties.leap.tls.message.client;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.util.List;

public final class ClientCertificateVerifyMessage extends TlsHandshakeMessage {
    public static final int ID = 0x0F;

    public ClientCertificateVerifyMessage(TlsVersion version, Source source) {
        super(version, source);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsEngineMode mode, Source source, List<Type> precedingMessages) {
        if(precedingMessages.isEmpty() || precedingMessages.getLast() != Type.CLIENT_KEY_EXCHANGE) {
            return false;
        }

        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsEngineMode.CLIENT;
                case REMOTE -> mode == TlsEngineMode.SERVER;
            };
            case UDP -> false;
        };
    }

    @Override
    public Type type() {
        return Type.CLIENT_CERTIFICATE_VERIFY;
    }

    @Override
    public ContentType contentType() {
        return ContentType.HANDSHAKE;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {

    }

    @Override
    public int handshakePayloadLength() {
        return 0;
    }
}
