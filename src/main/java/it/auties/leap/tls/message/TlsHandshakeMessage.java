package it.auties.leap.tls.message;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.implementation.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class TlsHandshakeMessage extends TlsMessage
        permits CertificateMessage, CertificateRequestMessage, CertificateVerifyMessage, ChangeCipherSpecMessage, FinishedMessage, HelloDoneMessage, HelloMessage, HelloRequestMessage, KeyExchangeMessage {
    protected TlsHandshakeMessage(TlsVersion version) {
        super(version, TlsSource.REMOTE);
    }

    protected TlsHandshakeMessage(TlsContext context) {
        var version = context.getNegotiatedValue(TlsProperty.version())
                .orElseGet(() -> getHighestNegotiableVersion(context));
        super(version, TlsSource.LOCAL);
    }

    private static TlsVersion getHighestNegotiableVersion(TlsContext context) {
        return context.getNegotiableValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()))
                .stream()
                .reduce((first, second) -> first.id().value() > second.id().value() ? first : second)
                .orElseThrow(() -> new TlsAlert("No version was set in the tls config"))
                .toLegacyVersion();
    }

    protected abstract int handshakePayloadLength();

    protected abstract void serializeHandshakePayload(ByteBuffer buffer);

    @Override
    public int payloadLength() {
        var handshakePayloadLength = handshakePayloadLength();
        return handshakePayloadHeaderLength(handshakePayloadLength) + handshakePayloadLength;
    }

    public static int handshakePayloadHeaderLength(int handshakePayloadLength) {
        return INT8_LENGTH + (handshakePayloadLength > 0 ? INT24_LENGTH : 0);
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
        var handshakePayloadLength = handshakePayloadLength();
        if (handshakePayloadLength > 0) {
            writeBigEndianInt24(buffer, handshakePayloadLength);
            serializeHandshakePayload(buffer);
        }
    }
}
