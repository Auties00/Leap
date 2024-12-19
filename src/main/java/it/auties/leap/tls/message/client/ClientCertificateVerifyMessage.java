package it.auties.leap.tls.message.client;

import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;

public final class ClientCertificateVerifyMessage extends TlsHandshakeMessage {
    public static final int ID = 0x0F;

    public ClientCertificateVerifyMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    @Override
    public byte id() {
        return ID;
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
