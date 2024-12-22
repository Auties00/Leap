package it.auties.leap.tls.message.client;

import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsVersionId;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.key.TlsCookie;
import it.auties.leap.tls.key.TlsRandomData;
import it.auties.leap.tls.key.TlsSharedSecret;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessage;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public final class ClientHelloMessage extends TlsHandshakeMessage {
    public static final int ID = 0x01;

    private final TlsRandomData randomData;
    private final TlsSharedSecret sessionId;
    private final TlsCookie cookie;
    private final List<Integer> ciphers;
    private final List<Byte> compressions;
    private final List<TlsExtension.Implementation> extensions;
    private final int extensionsLength;

    public ClientHelloMessage(TlsVersion tlsVersion, TlsSource source, TlsRandomData randomData, TlsSharedSecret sessionId, TlsCookie cookie, List<Integer> ciphers, List<Byte> compressions, List<TlsExtension.Implementation> extensions, int extensionsLength) {
        super(tlsVersion, source);
        this.randomData = randomData;
        this.sessionId = sessionId;
        this.cookie = cookie;
        this.ciphers = ciphers;
        this.compressions = compressions;
        this.extensions = extensions;
        this.extensionsLength = extensionsLength;
    }

    public static TlsMessage of(TlsVersion version, List<TlsExtension.Implementation.Decoder> decoders, TlsSource source, ByteBuffer buffer) {
        var versionId = TlsVersionId.of(readLittleEndianInt16(buffer));
        var tlsVersion = TlsVersion.of(versionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown version: " + versionId));
        var clientRandom = TlsRandomData.of(buffer);
        var sessionId = TlsSharedSecret.of(buffer);
        var cookie = TlsCookie.of(version, buffer)
                .orElse(null);
        var ciphersLength = readLittleEndianInt16(buffer);
        var ciphers = new ArrayList<Integer>();
        try(var _ = scopedRead(buffer, ciphersLength)) {
            while (buffer.hasRemaining()) {
                var cipherId = readLittleEndianInt16(buffer);
                ciphers.add(cipherId);
            }
        }
        var compressions = new ArrayList<Byte>();
        var compressionsLength = readLittleEndianInt16(buffer);
        try(var _ = scopedRead(buffer, compressionsLength)) {
            while (buffer.hasRemaining()) {
                var compressionId = readLittleEndianInt8(buffer);
                compressions.add(compressionId);
            }
        }
        var extensions = new ArrayList<TlsExtension.Implementation>();
        var extensionsLength = readLittleEndianInt16(buffer);
        try(var _ = scopedRead(buffer, extensionsLength)) {
            while (buffer.hasRemaining()) {
                var extensionType = readLittleEndianInt16(buffer);
                var extensionLength = readLittleEndianInt16(buffer);
                if(extensionLength == 0) {
                    continue;
                }

                for(var decoder : decoders) {
                    var extension = decoder.decodeClient(tlsVersion, extensionType, buffer, extensionLength);
                    if (extension.isPresent()) {
                        extensions.add(extension.get());
                        break;
                    }
                }
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
            writeLittleEndianInt16(payload, cipher);
        }

        writeLittleEndianInt8(payload, compressions.size());
        for(var compression : compressions) {
            writeLittleEndianInt8(payload, compression);
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

    public static int getMessagePayloadLength(TlsCookie cookie, List<Integer> ciphers, List<Byte> compressions) {
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
