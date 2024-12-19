package it.auties.leap.tls.message.client;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.readLittleEndianInt24;
import static it.auties.leap.tls.BufferHelper.scopedRead;

public final class ClientKeyExchangeMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x10;
    private final TlsKeyExchange.Client parameters;
    public ClientKeyExchangeMessage(TlsVersion tlsVersion, TlsSource source, TlsKeyExchange.Client parameters) {
        super(tlsVersion, source);
        this.parameters = parameters;
    }

    public static ClientKeyExchangeMessage of(TlsVersion version, TlsSource source, TlsCipher cipher, ByteBuffer buffer) {
        if(cipher == null) {
            throw new IllegalArgumentException("ServerKeyExchangeMessage was received before ServerHelloMessage, so no cipher was negotiated");
        }

        var messageLength = readLittleEndianInt24(buffer);
        try(var _ = scopedRead(buffer, messageLength)) {
            var parameters = TlsKeyExchange.Client.of(cipher, buffer);
            return new ClientKeyExchangeMessage(version, source, parameters);
        }
    }

    @Override
    public byte id() {
        return ID;
    }

    public TlsKeyExchange.Client parameters() {
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
