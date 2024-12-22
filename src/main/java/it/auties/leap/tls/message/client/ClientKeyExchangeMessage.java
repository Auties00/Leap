package it.auties.leap.tls.message.client;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferHelper.readLittleEndianInt24;
import static it.auties.leap.tls.util.BufferHelper.scopedRead;

public final class ClientKeyExchangeMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x10;
    private final TlsClientKeyExchange parameters;
    public ClientKeyExchangeMessage(TlsVersion tlsVersion, TlsSource source, TlsClientKeyExchange parameters) {
        super(tlsVersion, source);
        this.parameters = parameters;
    }

    public static ClientKeyExchangeMessage of(TlsVersion version, TlsSource source, TlsCipher cipher, ByteBuffer buffer) {
        if(cipher == null) {
            throw new IllegalArgumentException("ServerKeyExchangeMessage was received before ServerHelloMessage, so no cipher was negotiated");
        }

        var messageLength = readLittleEndianInt24(buffer);
        try(var _ = scopedRead(buffer, messageLength)) {
            var parameters = TlsClientKeyExchange.of(cipher, buffer);
            return new ClientKeyExchangeMessage(version, source, parameters);
        }
    }

    @Override
    public byte id() {
        return ID;
    }

    public TlsClientKeyExchange parameters() {
        return parameters;
    }

    @Override
    public Type type() {
        return Type.CLIENT_KEY_EXCHANGE;
    }

    @Override
    public ContentType contentType() {
        return ContentType.HANDSHAKE;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {
        parameters.serialize(buffer);
    }

    @Override
    public int handshakePayloadLength() {
        return parameters.length();
    }
}
