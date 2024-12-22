package it.auties.leap.tls.message;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.client.*;
import it.auties.leap.tls.message.server.*;

import java.nio.ByteBuffer;
import java.util.List;

public abstract sealed class TlsHandshakeMessage extends TlsMessage
        permits ClientCertificateMessage, ClientCertificateVerifyMessage, ClientChangeCipherSpecMessage,
        ClientFinishedMessage, ClientHelloMessage, ClientKeyExchangeMessage, ServerCertificateMessage,
                ServerCertificateRequestMessage, ServerChangeCipherSpecMessage, ServerFinishedMessage, ServerHelloDoneMessage,
                ServerHelloMessage, ServerHelloRequestMessage, ServerKeyExchangeMessage {
    protected static final int MIN_HASH_LENGTH = 12;

    protected TlsHandshakeMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static TlsMessage ofServer(TlsCipher cipher, List<TlsExtension.Implementation.Decoder> decoders, ByteBuffer buffer, Metadata metadata) {
        var version = metadata.version();
        var source = metadata.source();
        var id = readLittleEndianInt8(buffer);
        var messageLength = readLittleEndianInt24(buffer);
        try(var _ = scopedRead(buffer, messageLength)) {
            return switch (id) {
                case ServerHelloRequestMessage.ID -> ServerHelloRequestMessage.of(version, source, messageLength);
                case ServerHelloMessage.ID -> ServerHelloMessage.of(version, decoders, source, buffer);
                case ServerCertificateMessage.ID -> ServerCertificateMessage.of(version, source, buffer);
                case ServerKeyExchangeMessage.ID -> ServerKeyExchangeMessage.of(version, source, cipher, buffer);
                case ServerHelloDoneMessage.ID -> ServerHelloDoneMessage.of(version, source, messageLength);
                case ServerCertificateRequestMessage.ID -> ServerCertificateRequestMessage.of(version, source, buffer);
                case ServerFinishedMessage.ID -> ServerFinishedMessage.of(version, source, buffer);
                default -> throw new IllegalArgumentException("Cannot decode server message, unknown id: " + id);
            };
        }
    }

    public static TlsMessage ofClient(TlsCipher cipher, List<TlsExtension.Implementation.Decoder> decoders, ByteBuffer buffer, Metadata metadata) {
        var version = metadata.version();
        var source = metadata.source();
        var id = readLittleEndianInt8(buffer);
        var messageLength = readLittleEndianInt24(buffer);
        try(var _ = scopedRead(buffer, messageLength)) {
            return switch (id) {
                case ClientHelloMessage.ID -> ClientHelloMessage.of(version, decoders, source, buffer);
                case ClientCertificateMessage.ID -> ClientCertificateMessage.of(version, source, buffer);
                case ClientKeyExchangeMessage.ID -> ServerKeyExchangeMessage.of(version, source, cipher, buffer);
                case ClientFinishedMessage.ID -> ClientFinishedMessage.of(version, source, buffer);
                default -> throw new IllegalArgumentException("Cannot decode client message, unknown id: " + id);
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
        if(handshakePayloadLength > 0) {
            writeLittleEndianInt24(buffer, handshakePayloadLength);
            serializeHandshakePayload(buffer);
        }
    }
}
