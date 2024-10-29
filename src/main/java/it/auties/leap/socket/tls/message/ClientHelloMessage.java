package it.auties.leap.socket.tls.message;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.tls.*;

import java.security.SecureRandom;
import java.util.Set;

public final class ClientHelloMessage extends TlsMessage {
    private final TlsVersion tlsVersion;
    private final boolean useTls3;
    private final byte[] clientData;
    private final byte[] sessionId;
    private final byte[] cookie;
    private final Set<TlsCipher> ciphers;
    private final Set<TlsCompression> compressions;
    private final Set<TlsExtension> extensions;

    public ClientHelloMessage(TlsVersion version, Set<TlsCipher> ciphers, Set<TlsExtension> extensions, Set<TlsCompression> compressions, SecureRandom random) {
        this.tlsVersion = switch (version) {
            case TLS13 -> TlsVersion.TLS12;
            case DTLS13 -> TlsVersion.DTLS12;
            default -> version;
        };
        this.useTls3 = tlsVersion != version;
        this.clientData = new byte[32];
        random.nextBytes(clientData);
        this.sessionId = new byte[32];
        random.nextBytes(sessionId);
        this.cookie = version.protocol() == SocketProtocol.UDP ? new byte[0] : null;
        this.ciphers = ciphers;
        this.extensions = extensions;
        this.compressions = compressions;
    }

    @Override
    public byte id() {
        return 0x01;
    }

    @Override
    public byte[] serializeMessage() {
        try {
            var ciphersLength = ciphers.size() << 1;

            var extensionsLength = extensions.stream()
                    .mapToInt(TlsExtension::extensionLength)
                    .sum();
            var messageLength = INT16_LENGTH
                    + clientData.length
                    + INT8_LENGTH
                    + sessionId.length
                    + (cookie != null ? INT8_LENGTH + cookie.length : 0)
                    + INT16_LENGTH
                    + ciphersLength
                    + INT8_LENGTH
                    + compressions.size()
                    + (extensionsLength == 0 ? 0 : INT16_LENGTH + extensionsLength);
            var messageHeaderLength = INT8_LENGTH + INT24_LENGTH;
            var position = 0;
            var payload = new byte[TLS_HEADER_LENGTH + messageHeaderLength + messageLength];

            payload[position++] = ContentType.HANDSHAKE.id();
            payload[position++] = (byte) tlsVersion.major();
            payload[position++] = (byte) tlsVersion.minor();
            payload[position++] = (byte) ((messageHeaderLength + messageLength) >> 8);
            payload[position++] = (byte) (messageHeaderLength + messageLength);

            payload[position++] = id();
            payload[position++] = (byte) ((messageLength >> 16) & 0xFF);
            payload[position++] = (byte) ((messageLength >> 8) & 0xFF);
            payload[position++] = (byte) (messageLength & 0xFF);

            payload[position++] = (byte) (tlsVersion.id() >>> 8);
            payload[position++] = (byte) tlsVersion.id();

            System.arraycopy(clientData, 0, payload, position, clientData.length);
            position += clientData.length;

            payload[position++] = (byte) sessionId.length;
            System.arraycopy(sessionId, 0, payload, position, sessionId.length);
            position += sessionId.length;

            if(cookie != null) {
                payload[position++] = (byte) cookie.length;
                System.arraycopy(cookie, 0, payload, position, cookie.length);
                position += cookie.length;
            }

            payload[position++] = (byte) (ciphersLength >> 8);
            payload[position++] = (byte) ciphersLength;
            for (var cipher : ciphers) {
                payload[position++] = (byte) (cipher.id() >> 8);
                payload[position++] = (byte) cipher.id();
            }

            payload[position++] = (byte) compressions.size();
            for(var compression : compressions) {
                payload[position++] = compression.id();
            }

            if(!extensions.isEmpty()) {
                payload[position++] = (byte) (extensionsLength >> 8);
                payload[position++] = (byte) (extensionsLength);
                for (var extension : extensions) {
                    position = extension.serializeExtension(payload, position);
                }
            }

            if(position != payload.length) {
                throw new InternalError("Invalid payload size detected");
            }

            return payload;
        }catch (ArrayIndexOutOfBoundsException _) {
            throw new InternalError("Invalid payload size detected");
        }
    }
}
