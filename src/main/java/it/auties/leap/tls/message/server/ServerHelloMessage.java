package it.auties.leap.tls.message.server;

import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.key.TlsRandomData;
import it.auties.leap.tls.key.TlsSharedSecret;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public final class ServerHelloMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x02;

    private final TlsRandomData randomData;
    private final TlsSharedSecret sessionId;
    private final int cipher;
    private final int compression;
    private final List<TlsExtension> extensions;
    public ServerHelloMessage(TlsVersion version, TlsSource source, TlsRandomData randomData, TlsSharedSecret sessionId, int cipher, List<TlsExtension> extensions, int compression) {
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

    public int cipher() {
        return cipher;
    }

    public int compression() {
        return compression;
    }

    public List<TlsExtension> extensions() {
        return extensions;
    }

    public static ServerHelloMessage of(TlsVersion version, List<TlsExtension.Implementation.Decoder> decoders, TlsSource source, ByteBuffer buffer) {
        var tlsVersionId = readLittleEndianInt16(buffer);
        var tlsVersion = TlsVersion.of(tlsVersionId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: " + tlsVersionId));

        var serverRandom = TlsRandomData.of(buffer);

        var sessionId = TlsSharedSecret.of(buffer);

        var cipherId = readLittleEndianInt16(buffer);

        var compressionMethodId = readLittleEndianInt8(buffer);

        var extensions = new ArrayList<TlsExtension>();
        if(buffer.remaining() >= INT16_LENGTH) {
            var extensionsLength = readLittleEndianInt16(buffer);
            try (var _ = scopedRead(buffer, extensionsLength)) {
                while (buffer.hasRemaining()) {
                    var extensionType = readLittleEndianInt16(buffer);
                    var extensionLength = readLittleEndianInt16(buffer);
                    if (extensionLength == 0) {
                        continue;
                    }

                    for(var decoder : decoders) {
                        var extension = decoder.decodeServer(tlsVersion, extensionType, buffer, extensionLength);
                        if (extension.isPresent()) {
                            extensions.add(extension.get());
                            break;
                        }
                    }
                }
            }
        }
        return new ServerHelloMessage(tlsVersion, source, serverRandom, sessionId, cipherId, extensions, compressionMethodId);
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
