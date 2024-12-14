package it.auties.leap.tls.message.client;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsCompression;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.TlsVersionId;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.crypto.key.TlsCookie;
import it.auties.leap.tls.crypto.key.TlsRandomData;
import it.auties.leap.tls.crypto.key.TlsSharedSecret;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.TlsBuffer.*;

public final class ClientHelloMessage extends TlsHandshakeMessage {
    public static final int ID = 0x01;

    private final TlsRandomData randomData;
    private final TlsSharedSecret sessionId;
    private final TlsCookie cookie;
    private final List<TlsCipher> ciphers;
    private final List<TlsCompression> compressions;
    private final List<TlsConcreteExtension> extensions;
    private final int extensionsLength;

    public ClientHelloMessage(TlsVersion tlsVersion, Source source, TlsRandomData randomData, TlsSharedSecret sessionId, TlsCookie cookie, List<TlsCipher> ciphers, List<TlsCompression> compressions, List<TlsConcreteExtension> extensions, int extensionsLength) {
        super(tlsVersion, source);
        this.randomData = randomData;
        this.sessionId = sessionId;
        this.cookie = cookie;
        this.ciphers = ciphers;
        this.compressions = compressions;
        this.extensions = new ArrayList<>();
        for(var extension : extensions) {
            if(extension instanceof TlsConcreteExtension concreteExtension) {
                this.extensions.add(concreteExtension);
            }
        }
        this.extensionsLength = extensionsLength;
    }

    public static TlsMessage of(TlsVersion version, Source source, ByteBuffer buffer) {
        var versionId = new TlsVersionId(readLittleEndianInt16(buffer));
        var tlsVersion = TlsVersion.of(versionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown version: " + versionId));
        var clientRandom = TlsRandomData.of(buffer);
        var sessionId = TlsSharedSecret.of(buffer);
        var cookie = TlsCookie.of(version, buffer)
                .orElse(null);
        var ciphersLength = readLittleEndianInt16(buffer);
        var ciphers = new ArrayList<TlsCipher>();
        try(var _ = scopedRead(buffer, ciphersLength)) {
            while (buffer.hasRemaining()) {
                var cipherId = readLittleEndianInt16(buffer);
                var cipher = TlsCipher.of(cipherId);
                if(cipher.isEmpty()) {
                    continue;
                }

                ciphers.add(cipher.get());
            }
        }
        var compressions = new ArrayList<TlsCompression>();
        var compressionsLength = readLittleEndianInt16(buffer);
        try(var _ = scopedRead(buffer, compressionsLength)) {
            while (buffer.hasRemaining()) {
                var compressionId = readLittleEndianInt8(buffer);
                var compression = TlsCompression.of(compressionId);
                if(compression.isEmpty()) {
                    continue;
                }

                compressions.add(compression.get());
            }
        }
        var extensions = new ArrayList<TlsConcreteExtension>();
        var extensionsLength = readLittleEndianInt16(buffer);
        try(var _ = scopedRead(buffer, extensionsLength)) {
            while (buffer.hasRemaining()) {
                var extensionType = readLittleEndianInt16(buffer);
                var extensionLength = readLittleEndianInt16(buffer);
                if(extensionLength == 0) {
                    continue;
                }

                var extension = TlsConcreteExtension.ofServer(tlsVersion, extensionType, buffer, extensionLength);
                if (extension.isEmpty()) {
                    continue;
                }

                extensions.add(extension.get());
            }
        }
        return new ClientHelloMessage(tlsVersion, source, clientRandom, sessionId, cookie, ciphers, compressions, extensions, extensionsLength);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public Type type() {
        return Type.CLIENT_HELLO;
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsEngineMode mode, Source source, List<Type> precedingMessages) {
        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> precedingMessages.isEmpty();
                case REMOTE -> mode == TlsEngineMode.SERVER;
            };
            case UDP -> false;
        };
    }

    @Override
    public ContentType contentType() {
        return ContentType.HANDSHAKE;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer payload) {
        var encodedVersion = switch (version) {
            case TLS13 -> TlsVersion.TLS12;
            case DTLS13 -> TlsVersion.DTLS12;
            default -> version;
        };
        writeLittleEndianInt16(payload, encodedVersion.id().value());

        randomData.serialize(payload);

        sessionId.serialize(payload);

        if(cookie != null) {
            cookie.serialize(payload);
        }

        var ciphersLength = ciphers.size() * INT16_LENGTH;
        writeLittleEndianInt16(payload, ciphersLength);
        for (var cipher : ciphers) {
            writeLittleEndianInt16(payload, cipher.id());
        }

        writeLittleEndianInt8(payload, compressions.size());
        for(var compression : compressions) {
            writeLittleEndianInt8(payload, compression.id());
        }

        if(!extensions.isEmpty()) {
            writeLittleEndianInt16(payload, extensionsLength);
            for (var extension : extensions) {
                extension.serializeExtension(payload);
            }
        }
    }

    @Override
    public int handshakePayloadLength() {
        var messagePayloadNoExtensionsLength = getMessagePayloadLength(cookie, ciphers, compressions);
        return messagePayloadNoExtensionsLength
                + INT16_LENGTH + extensionsLength;
    }

    public static int getMessagePayloadLength(TlsCookie cookie, List<TlsCipher> ciphers, List<TlsCompression> compressions) {
        return INT16_LENGTH
                + TlsRandomData.length()
                + INT8_LENGTH + TlsSharedSecret.length()
                + (cookie != null ? INT8_LENGTH + cookie.length() : 0)
                + INT16_LENGTH + ciphers.size() * INT16_LENGTH
                + INT8_LENGTH + compressions.size() * INT8_LENGTH;
    }

    public TlsRandomData randomData() {
        return randomData;
    }

    public TlsSharedSecret sessionId() {
        return sessionId;
    }
}
