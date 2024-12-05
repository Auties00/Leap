package it.auties.leap.tls.message.server;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsCompression;
import it.auties.leap.tls.TlsExtension;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.extension.TlsConcreteExtension;
import it.auties.leap.tls.key.TlsRandomData;
import it.auties.leap.tls.key.TlsSharedSecret;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.TlsRecord.*;

public final class ServerHelloMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x02;

    private final TlsRandomData randomData;
    private final TlsSharedSecret sessionId;
    private final TlsCipher cipher;
    private final TlsCompression compression;
    private final List<TlsExtension> extensions;
    public ServerHelloMessage(TlsVersion version, Source source, TlsRandomData randomData, TlsSharedSecret sessionId, TlsCipher cipher, List<TlsExtension> extensions, TlsCompression compression) {
        super(version, source);
        this.randomData = randomData;
        this.sessionId = sessionId;
        this.cipher = cipher;
        this.extensions = extensions;
        this.compression = compression;
    }

    public TlsRandomData randomData() {
        return randomData;
    }

    public TlsSharedSecret sessionId() {
        return sessionId;
    }

    public TlsCipher cipher() {
        return cipher;
    }

    public TlsCompression compression() {
        return compression;
    }

    public List<TlsExtension> extensions() {
        return extensions;
    }

    public static ServerHelloMessage of(TlsVersion version, Source source, ByteBuffer buffer) {
        var tlsVersionId = readInt16(buffer);
        var tlsVersion = TlsVersion.of(tlsVersionId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: " + tlsVersionId));

        var serverRandom = TlsRandomData.of(buffer);

        var sessionId = TlsSharedSecret.of(buffer);

        var cipherId = readInt16(buffer);
        var cipher = TlsCipher.of(cipherId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown cipher id: " + cipherId));

        var compressionMethodId = readInt8(buffer);
        var compressionMethod = TlsCompression.of(compressionMethodId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown compression method id: " + compressionMethodId));

        var extensions = new ArrayList<TlsExtension>();
        if(buffer.remaining() >= INT16_LENGTH) {
            var extensionsLength = readInt16(buffer);
            try (var _ = scopedRead(buffer, extensionsLength)) {
                while (buffer.hasRemaining()) {
                    var extensionType = readInt16(buffer);
                    var extensionLength = readInt16(buffer);
                    if (extensionLength == 0) {
                        continue;
                    }

                    var extension = TlsConcreteExtension.ofServer(tlsVersion, extensionType, buffer, extensionLength);
                    if (extension.isEmpty()) {
                        continue;
                    }
                    extensions.add(extension.get());
                }
            }
        }
        return new ServerHelloMessage(tlsVersion, source, serverRandom, sessionId, cipher, extensions, compressionMethod);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public Type type() {
        return Type.SERVER_HELLO;
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsEngineMode mode, Source source, List<Type> precedingMessages) {
        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> precedingMessages.isEmpty();
                case REMOTE -> mode == TlsEngineMode.CLIENT;
            };
            case UDP -> false;
        };
    }

    @Override
    public ContentType contentType() {
        return ContentType.HANDSHAKE;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {

    }

    @Override
    public int handshakePayloadLength() {
        return 0;
    }
}
