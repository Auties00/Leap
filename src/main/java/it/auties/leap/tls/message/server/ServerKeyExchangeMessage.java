package it.auties.leap.tls.message.server;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;

public final class ServerKeyExchangeMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0C;

    private final TlsServerKeyExchange keyExchange;
    private final int signatureAlgorithm;
    private final byte[] signature;
    public ServerKeyExchangeMessage(TlsVersion tlsVersion, TlsSource source, TlsServerKeyExchange keyExchange, int signatureAlgorithm, byte[] signature) {
        super(tlsVersion, source);
        this.keyExchange = keyExchange;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    public static ServerKeyExchangeMessage of(TlsVersion version, TlsSource source, TlsCipher cipher, ByteBuffer buffer) {
        if(cipher == null) {
            throw new IllegalArgumentException("ServerKeyExchangeMessage was received before ServerHelloMessage, so no cipher was negotiated");
        }

        var parameters = TlsServerKeyExchange.of(cipher, buffer);
        var signatureAlgorithmId = readLittleEndianInt16(buffer);
        var signature = readBytesLittleEndian16(buffer);
        return new ServerKeyExchangeMessage(version, source, parameters, signatureAlgorithmId, signature);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public Type type() {
        return Type.SERVER_KEY_EXCHANGE;
    }

    public TlsServerKeyExchange keyExchange() {
        return keyExchange;
    }

    public int signatureAlgorithm() {
        return signatureAlgorithm;
    }

    public byte[] signature() {
        return signature;
    }

    @Override
    public ContentType contentType() {
        return ContentType.HANDSHAKE;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {
        keyExchange.serialize(buffer);
        writeLittleEndianInt16(buffer, signatureAlgorithm);
        writeBytesLittleEndian16(buffer, signature);
    }

    @Override
    public int handshakePayloadLength() {
        return keyExchange.length() + INT16_LENGTH + INT16_LENGTH + signature.length;
    }

}
