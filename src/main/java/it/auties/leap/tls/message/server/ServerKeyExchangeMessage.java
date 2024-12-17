package it.auties.leap.tls.message.server;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.config.TlsIdentifiableUnion;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.key.TlsSignatureAndHashAlgorithm;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.BufferHelper.*;

public final class ServerKeyExchangeMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0C;

    private final TlsKeyExchange.Server keyExchange;
    private final TlsIdentifiableUnion<TlsSignatureAndHashAlgorithm, Integer> signatureAlgorithm;
    private final byte[] signature;
    public ServerKeyExchangeMessage(TlsVersion tlsVersion, Source source, TlsKeyExchange.Server keyExchange, TlsIdentifiableUnion<TlsSignatureAndHashAlgorithm, Integer> signatureAlgorithm, byte[] signature) {
        super(tlsVersion, source);
        this.keyExchange = keyExchange;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    public static ServerKeyExchangeMessage of(TlsVersion version, Source source, TlsCipher cipher, ByteBuffer buffer) {
        if(cipher == null) {
            throw new IllegalArgumentException("ServerKeyExchangeMessage was received before ServerHelloMessage, so no cipher was negotiated");
        }

        var parameters = TlsKeyExchangeType.TlsServerKeyExchange.of(cipher, buffer);
        var signatureAlgorithmId = readLittleEndianInt16(buffer);
        var signature = readBytesLittleEndian16(buffer);
        return new ServerKeyExchangeMessage(version, source, parameters, TlsIdentifiableUnion.of(signatureAlgorithmId), signature);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public Type type() {
        return Type.SERVER_KEY_EXCHANGE;
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsMode mode, Source source, List<Type> precedingMessages) {
        if(precedingMessages.isEmpty() || (precedingMessages.getLast() != Type.SERVER_CERTIFICATE_REQUEST && precedingMessages.getLast() != Type.SERVER_CERTIFICATE)) {
            return false;
        }

        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsMode.SERVER;
                case REMOTE -> mode == TlsMode.CLIENT;
            };
            case UDP -> false;
        };
    }

    public TlsKeyExchange keyExchange() {
        return keyExchange;
    }

    public TlsIdentifiableUnion<TlsSignatureAndHashAlgorithm, Integer> signatureAlgorithm() {
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
