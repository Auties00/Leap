package it.auties.leap.socket.tls.message;

import it.auties.leap.socket.tls.TlsRecord;
import it.auties.leap.socket.tls.TlsVersion;

public abstract class TlsMessage implements TlsRecord {
    public abstract byte id();
    public abstract byte[] serializeMessage();

    public enum ContentType {
        INVALID((byte) 0, "invalid", TlsVersion.TLS13),
        CHANGE_CIPHER_SPEC((byte) 20, "change_cipher_spec", TlsVersion.TLS12),
        ALERT((byte) 21, "alert", TlsVersion.TLS13),
        HANDSHAKE((byte) 22, "handshake", TlsVersion.TLS13),
        APPLICATION_DATA((byte) 23, "application_data", TlsVersion.TLS12);

        private final byte id;
        private final String contentName;
        private final TlsVersion contentMaxVersion;
        ContentType(byte id, String contentName, TlsVersion contentMaxVersion) {
            this.id = id;
            this.contentName = contentName;
            this.contentMaxVersion = contentMaxVersion;
        }

        public byte id() {
            return id;
        }

        public String contentName() {
            return contentName;
        }

        public TlsVersion contentMaxVersion() {
            return contentMaxVersion;
        }
    }
}
