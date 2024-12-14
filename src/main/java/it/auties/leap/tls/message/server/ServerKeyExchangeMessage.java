package it.auties.leap.tls.message.server;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsSignatureAlgorithm;
import it.auties.leap.tls.TlsSpecificationException;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.crypto.key.TlsServerKey;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.TlsBuffer.*;

public final class ServerKeyExchangeMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0C;

    private final TlsServerKey parameters;
    private final TlsSignatureAlgorithm signatureAlgorithm;
    private final byte[] signature;
    public ServerKeyExchangeMessage(TlsVersion tlsVersion, Source source, TlsServerKey parameters, TlsSignatureAlgorithm signatureAlgorithm, byte[] signature) {
        super(tlsVersion, source);
        this.parameters = parameters;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    public static ServerKeyExchangeMessage of(TlsVersion version, Source source, TlsCipher cipher, ByteBuffer buffer) {
        if(cipher == null) {
            throw new IllegalArgumentException("ServerKeyExchangeMessage was received before ServerHelloMessage, so no cipher was negotiated");
        }

        var parameters = TlsServerKey.of(cipher, buffer);
        var signatureAlgorithmId = readLittleEndianInt16(buffer);
        var signatureAlgorithm = switch (version) {
            case TLS13, DTLS13 -> TlsSignatureAlgorithm.ofTlsV13(signatureAlgorithmId);
            case TLS12, DTLS12 -> TlsSignatureAlgorithm.ofTlsV12(signatureAlgorithmId)
                    .orElseThrow(() -> new TlsSpecificationException("Malformed signature algorithm: " + signatureAlgorithmId, URI.create("https://www.ietf.org/rfc/rfc5246.txt"), "7.4.1.4.1"));
            default -> throw new UnsupportedOperationException(); // TODO: Support other tls versions
        };
        var signature = readBytesLittleEndian16(buffer);
        return new ServerKeyExchangeMessage(version, source, parameters, signatureAlgorithm, signature);
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
    public boolean isSupported(TlsVersion version, TlsEngineMode mode, Source source, List<Type> precedingMessages) {
        if(precedingMessages.isEmpty() || (precedingMessages.getLast() != Type.SERVER_CERTIFICATE_REQUEST && precedingMessages.getLast() != Type.SERVER_CERTIFICATE)) {
            return false;
        }

        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsEngineMode.SERVER;
                case REMOTE -> mode == TlsEngineMode.CLIENT;
            };
            case UDP -> false;
        };
    }

    public TlsServerKey parameters() {
        return parameters;
    }

    public TlsSignatureAlgorithm signatureAlgorithm() {
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
        parameters.serialize(buffer);
        writeLittleEndianInt16(buffer, signatureAlgorithm.id());
        writeBytesLittleEndian16(buffer, signature);
    }

    @Override
    public int handshakePayloadLength() {
        return parameters.length() + INT16_LENGTH + INT16_LENGTH + signature.length;
    }

}
