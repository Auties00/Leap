package it.auties.leap.tls.message;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.message.implementation.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class TlsHandshakeMessage extends TlsMessage
        permits CertificateMessage, CertificateRequestMessage, CertificateVerifyMessage, ChangeCipherSpecMessage, FinishedMessage, HelloDoneMessage, HelloMessage, HelloRequestMessage, KeyExchangeMessage {
    protected TlsHandshakeMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static TlsHandshakeMessage of(TlsEngine engine, ByteBuffer buffer, Metadata metadata) {
        var id = readLittleEndianInt8(buffer);
        var messageLength = readLittleEndianInt24(buffer);
        try (var _ = scopedRead(buffer, messageLength)) {
            return switch (engine.selectedMode().orElse(null)) {
                case CLIENT -> switch (id) {
                    case HelloRequestMessage.Server.ID -> HelloRequestMessage.Server.of(engine, buffer, metadata);
                    case HelloMessage.Server.ID -> HelloMessage.Server.of(engine, buffer, metadata);
                    case CertificateMessage.Server.ID -> CertificateMessage.Server.of(engine, buffer, metadata);
                    case KeyExchangeMessage.Server.ID -> KeyExchangeMessage.Server.of(engine, buffer, metadata);
                    case HelloDoneMessage.Server.ID -> HelloDoneMessage.Server.of(engine, buffer, metadata);
                    case CertificateRequestMessage.Server.ID -> CertificateRequestMessage.Server.of(engine, buffer, metadata);
                    case FinishedMessage.Server.ID -> FinishedMessage.Server.of(engine, buffer, metadata);
                    default -> throw new IllegalArgumentException("Cannot decode server message, unknown id: " + id);
                };
                case SERVER -> switch (id) {
                    case HelloMessage.Client.ID -> HelloMessage.Client.of(engine, buffer, metadata);
                    case CertificateMessage.Client.ID -> CertificateMessage.Client.of(engine, buffer, metadata);
                    case KeyExchangeMessage.Client.ID -> KeyExchangeMessage.Client.of(engine, buffer, metadata);
                    case FinishedMessage.Client.ID -> FinishedMessage.Client.of(engine, buffer, metadata);
                    default -> throw new IllegalArgumentException("Cannot decode client message, unknown id: " + id);
                };
                case null -> throw new TlsException("No engine mode has been selected yet");
            };
        }
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
        writeLittleEndianInt8(buffer, id());
        var handshakePayloadLength = handshakePayloadLength();
        if (handshakePayloadLength > 0) {
            writeLittleEndianInt24(buffer, handshakePayloadLength);
            serializeHandshakePayload(buffer);
        }
    }
}
