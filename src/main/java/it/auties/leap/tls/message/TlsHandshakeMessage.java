package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.implementation.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class TlsHandshakeMessage extends TlsMessage
        permits CertificateMessage, CertificateRequestMessage, CertificateVerifyMessage, ChangeCipherSpecMessage, FinishedMessage, HelloDoneMessage, HelloMessage, HelloRequestMessage, KeyExchangeMessage {
    protected TlsHandshakeMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    protected abstract int handshakePayloadLength();

    protected abstract void serializeHandshakePayload(ByteBuffer buffer);

    @Override
    public int messagePayloadLength() {
        var handshakePayloadLength = handshakePayloadLength();
        return handshakePayloadHeaderLength(handshakePayloadLength) + handshakePayloadLength;
    }

    public static int handshakePayloadHeaderLength(int handshakePayloadLength) {
        return INT8_LENGTH + (handshakePayloadLength > 0 ? INT24_LENGTH : 0);
    }

    @Override
    public void serializeMessagePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
        var handshakePayloadLength = handshakePayloadLength();
        if (handshakePayloadLength > 0) {
            writeBigEndianInt24(buffer, handshakePayloadLength);
            serializeHandshakePayload(buffer);
        }
    }
}
