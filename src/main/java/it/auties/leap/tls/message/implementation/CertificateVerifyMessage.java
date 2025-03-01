package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageType;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

public sealed abstract class CertificateVerifyMessage extends TlsHandshakeMessage {
    public static final int ID = 0x0F;

    CertificateVerifyMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Client extends CertificateVerifyMessage {
        public Client(TlsVersion version, TlsSource source) {
            super(version, source);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public TlsMessageType type() {
            return TlsMessageType.CLIENT_CERTIFICATE_VERIFY;
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
