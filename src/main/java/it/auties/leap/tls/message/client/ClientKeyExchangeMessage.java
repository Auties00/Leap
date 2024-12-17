package it.auties.leap.tls.message.client;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.BufferHelper.readLittleEndianInt24;
import static it.auties.leap.tls.BufferHelper.scopedRead;

public final class ClientKeyExchangeMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x10;
    private final TlsPreMasterSecretKey parameters;
    public ClientKeyExchangeMessage(TlsVersion tlsVersion, Source source, TlsPreMasterSecretKey parameters) {
        super(tlsVersion, source);
        this.parameters = parameters;
    }

    public static ClientKeyExchangeMessage of(TlsVersion version, Source source, TlsCipher cipher, ByteBuffer buffer) {
        if(cipher == null) {
            throw new IllegalArgumentException("ServerKeyExchangeMessage was received before ServerHelloMessage, so no cipher was negotiated");
        }

        var messageLength = readLittleEndianInt24(buffer);
        try(var _ = scopedRead(buffer, messageLength)) {
            var parameters = TlsPreMasterSecretKey.of(cipher, buffer);
            return new ClientKeyExchangeMessage(version, source, parameters);
        }
    }

    @Override
    public byte id() {
        return ID;
    }

    public TlsPreMasterSecretKey parameters() {
        return parameters;
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsMode mode, Source source, List<Type> precedingMessages) {
        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsMode.CLIENT
                        && !precedingMessages.isEmpty()
                        && (precedingMessages.getLast() == Type.CLIENT_CERTIFICATE || precedingMessages.getLast() == Type.SERVER_HELLO_DONE);
                case REMOTE -> mode == TlsMode.SERVER;
            };
            case UDP -> false;
        };
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
