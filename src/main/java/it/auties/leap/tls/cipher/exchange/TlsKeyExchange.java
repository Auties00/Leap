package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.nio.ByteBuffer;
import java.util.Objects;

public sealed interface TlsKeyExchange {
    static TlsKeyExchange none() {
        return null;
    }

    static TlsKeyExchange dh() {
        return null;
    }

    static TlsKeyExchange dhe() {
        return null;
    }

    static TlsKeyExchange eccPwd() {
        return null;
    }

    static TlsKeyExchange ecdh() {
        return null;
    }

    static TlsKeyExchange ecdhe() {
        return null;
    }

    static TlsKeyExchange gostr256() {
        return null;
    }

    static TlsKeyExchange krb5() {
        return null;
    }

    static TlsKeyExchange psk() {
        return null;
    }

    static TlsKeyExchange rsa() {
        return null;
    }

    static TlsKeyExchange srp() {
        return null;
    }
    
    non-sealed abstract class Client implements TlsKeyExchange {
        protected Client(TlsVersion version, TlsSupportedGroup group) {
            Objects.requireNonNull(version, "Invalid input version");
            Objects.requireNonNull(group, "Invalid input group");
        }

        protected Client(ByteBuffer buffer) {
            Objects.requireNonNull(buffer, "Invalid input buffer");
        }

        public abstract void serialize(ByteBuffer buffer);
        public abstract int length();
    }

    non-sealed abstract class Server implements TlsKeyExchange {
        protected Server(TlsVersion version, TlsSupportedGroup group) {
            Objects.requireNonNull(version, "Invalid input version");
            Objects.requireNonNull(group, "Invalid input group");
        }

        protected Server(ByteBuffer buffer) {
            Objects.requireNonNull(buffer, "Invalid input buffer");
        }

        public abstract void serialize(ByteBuffer buffer);
        public abstract int length();
        public abstract byte[] generatePreMasterSecret(Client clientKeyExchange);
    }
}
