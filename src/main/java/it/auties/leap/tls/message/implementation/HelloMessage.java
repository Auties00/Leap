package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class HelloMessage extends TlsHandshakeMessage {
    private static final int CLIENT_RANDOM_LENGTH = 32;
    private static final int SESSION_ID_LENGTH = 32;
    private static final int RANDOM_COOKIE_LENGTH = 32;
    HelloMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Client extends HelloMessage {
        public static final int ID = 0x01;

        private final byte[] randomData;
        private final byte[] sessionId;
        private final byte[] cookie;
        private final List<Integer> ciphers;
        private final List<Byte> compressions;
        private final List<TlsExtension.Concrete> extensions;
        private final int extensionsLength;

        public Client(TlsVersion version, TlsSource source, byte[] randomData, byte[] sessionId, byte[] cookie, List<Integer> ciphers, List<Byte> compressions, List<TlsExtension.Concrete> extensions, int extensionsLength) {
            super(version, source);
            this.randomData = randomData;
            this.sessionId = sessionId;
            this.cookie = cookie;
            this.ciphers = ciphers;
            this.compressions = compressions;
            this.extensions = extensions;
            this.extensionsLength = extensionsLength;
        }

        public static Client of(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var versionId = TlsVersionId.of(readBigEndianInt16(buffer));
            var tlsVersion = TlsVersion.of(versionId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown version: " + versionId));
            var clientRandom = readBytes(buffer, CLIENT_RANDOM_LENGTH);
            var sessionId = readBytesBigEndian8(buffer);
            var cookie = switch (metadata.version().protocol()) {
                case TCP -> null;
                case UDP -> readBytesBigEndian8(buffer);
            };
            var ciphersLength = readBigEndianInt16(buffer);
            var ciphers = new ArrayList<Integer>();
            try(var _ = scopedRead(buffer, ciphersLength)) {
                while (buffer.hasRemaining()) {
                    var cipherId = readBigEndianInt16(buffer);
                    ciphers.add(cipherId);
                }
            }
            var compressions = new ArrayList<Byte>();
            var compressionsLength = readBigEndianInt16(buffer);
            try(var _ = scopedRead(buffer, compressionsLength)) {
                while (buffer.hasRemaining()) {
                    var compressionId = readBigEndianInt8(buffer);
                    compressions.add(compressionId);
                }
            }
            var extensions = new ArrayList<TlsExtension.Concrete>();
            var extensionsLength = readBigEndianInt16(buffer);
            try(var _ = scopedRead(buffer, extensionsLength)) {
                while (buffer.hasRemaining()) {
                    var extensionType = readBigEndianInt16(buffer);
                    var extensionLength = readBigEndianInt16(buffer);
                    if(extensionLength == 0) {
                        continue;
                    }

                    for(var configurable : context.config().extensions()) {
                        var extension = configurable.decoder()
                                .deserialize(buffer, TlsSource.REMOTE, TlsMode.SERVER, extensionType);
                        if (extension.isPresent()) {
                            extensions.add(extension.get());
                            break;
                        }
                    }
                }
            }
            return new Client(tlsVersion, metadata.source(), clientRandom, sessionId, cookie, ciphers, compressions, extensions, extensionsLength);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public TlsMessageContentType contentType() {
            return TlsMessageContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer payload) {
            var encodedVersion = switch (version) {
                case TLS13 -> TlsVersion.TLS12;
                case DTLS13 -> TlsVersion.DTLS12;
                default -> version;
            };
            writeBigEndianInt16(payload, encodedVersion.id().value());

            writeBytes(payload, randomData);

            writeBytesBigEndian8(payload, sessionId);

            if(cookie != null) {
                writeBytesBigEndian8(payload, cookie);
            }

            var ciphersLength = getCiphersCount() * INT16_LENGTH;
            writeBigEndianInt16(payload, ciphersLength);
            for (var cipher : ciphers) {
                writeBigEndianInt16(payload, cipher);
            }

            var compressionsLength = getCompressionsCount() * INT8_LENGTH;
            writeBigEndianInt8(payload, compressionsLength);
            for (var compression : compressions) {
                writeBigEndianInt8(payload, compression);
            }

            if(!extensions.isEmpty()) {
                writeBigEndianInt16(payload, extensionsLength);
                for (var extension : extensions) {
                    extension.serializeExtension(payload);
                }
            }
        }

        @Override
        public int handshakePayloadLength() {
            var messagePayloadNoExtensionsLength = getMessagePayloadLength(cookie, getCiphersCount(), getCompressionsCount());
            return messagePayloadNoExtensionsLength
                    + INT16_LENGTH + extensionsLength;
        }

        private int getCiphersCount() {
            return ciphers.size();
        }

        private int getCompressionsCount() {
            return compressions.size();
        }

        public static int getMessagePayloadLength(byte[] cookie, int ciphers, int compressions) {
            return INT16_LENGTH
                    + CLIENT_RANDOM_LENGTH
                    + INT8_LENGTH + SESSION_ID_LENGTH
                    + (cookie != null ? INT8_LENGTH + RANDOM_COOKIE_LENGTH : 0)
                    + INT16_LENGTH + ciphers * INT16_LENGTH
                    + INT8_LENGTH + compressions * INT8_LENGTH;
        }

        public byte[] randomData() {
            return randomData;
        }

        public byte[] sessionId() {
            return sessionId;
        }

        public byte[] cookie() {
            return cookie;
        }

        public List<Integer> ciphers() {
            return ciphers;
        }

        public List<Byte> compressions() {
            return compressions;
        }

        public List<TlsExtension.Concrete> extensions() {
            return extensions;
        }

        public int extensionsLength() {
            return extensionsLength;
        }
    }

    public static final class Server extends HelloMessage {
        public static final byte ID = 0x02;

        private final byte[] randomData;
        private final byte[] sessionId;
        private final int cipher;
        private final byte compression;
        private final List<TlsExtension> extensions;

        public Server(TlsVersion version, TlsSource source, byte[] randomData, byte[] sessionId, int cipher, List<TlsExtension> extensions, byte compression) {
            super(version, source);
            this.randomData = randomData;
            this.sessionId = sessionId;
            this.cipher = cipher;
            this.extensions = extensions;
            this.compression = compression;
        }

        public static Server of(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var tlsVersionId = readBigEndianInt16(buffer);
            var tlsVersion = TlsVersion.of(tlsVersionId)
                    .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: " + tlsVersionId));

            var serverRandom = readBytes(buffer, CLIENT_RANDOM_LENGTH);

            var sessionId = readBytesBigEndian8(buffer);

            var cipherId = readBigEndianInt16(buffer);

            var compressionMethodId = readBigEndianInt8(buffer);

            var extensionTypeToDecoder = context.config()
                    .extensions()
                    .stream()
                    .collect(Collectors.toUnmodifiableMap(TlsExtension::extensionType, TlsExtension::decoder));
            var extensions = new ArrayList<TlsExtension>();
            if(buffer.remaining() >= INT16_LENGTH) {
                var extensionsLength = readBigEndianInt16(buffer);
                try (var _ = scopedRead(buffer, extensionsLength)) {
                    while (buffer.hasRemaining()) {
                        var extensionType = readBigEndianInt16(buffer);
                        var extensionLength = readBigEndianInt16(buffer);
                        if (extensionLength == 0) {
                            continue;
                        }

                        var extensionDecoder = extensionTypeToDecoder.get(extensionType);
                        if(extensionDecoder == null) {
                            throw new TlsException("Unknown extension");
                        }

                        System.out.println("Decoding " + extensionDecoder.toConcreteType(TlsSource.REMOTE, TlsMode.CLIENT).getName());
                        try(var _ = scopedRead(buffer, extensionLength)) {
                            extensionDecoder.deserialize(buffer, TlsSource.REMOTE, TlsMode.CLIENT, extensionType)
                                    .ifPresent(extensions::add);
                        }
                    }
                }
            }
            return new Server(tlsVersion, metadata.source(), serverRandom, sessionId, cipherId, extensions, compressionMethodId);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public TlsMessageContentType contentType() {
            return TlsMessageContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {

        }

        @Override
        public int handshakePayloadLength() {
            return 0;
        }

        public byte[] randomData() {
            return randomData;
        }

        public byte[] sessionId() {
            return sessionId;
        }

        public int cipher() {
            return cipher;
        }

        public byte compression() {
            return compression;
        }

        public List<TlsExtension> extensions() {
            return extensions;
        }
    }
}
