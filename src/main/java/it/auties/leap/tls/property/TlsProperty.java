package it.auties.leap.tls.property;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;

import java.net.InetSocketAddress;
import java.util.Objects;

@SuppressWarnings("unused")
public sealed abstract class TlsProperty<V> {
    public static Identifiable<Integer, TlsCipher> ciphers() {
        return Identifiable.CIPHERS;
    }

    public static Identifiable<Byte, TlsCompression> compressions() {
        return Identifiable.COMPRESSIONS;
    }

    public static Value<Boolean> extendedMasterSecret() {
        return Value.EXTENDED_MASTER_SECRET;
    }

    public static Value<InetSocketAddress> remoteAddress() {
        return Value.REMOTE_ADDRESS;
    }

    public static <K, V extends TlsIdentifiable<K>> Identifiable<K, V> identifiable(String key, boolean negotiable) {
        return new Identifiable<>(key, negotiable);
    }

    public static <V> Value<V> value(String key, boolean negotiable) {
        return new Value<>(key, negotiable);
    }

    final String id;
    final boolean negotiable;
    private TlsProperty(String id, boolean negotiable) {
        this.id = id;
        this.negotiable = negotiable;
    }

    public String id() {
        return id;
    }

    public boolean negotiable() {
        return negotiable;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsProperty<?> that
                && Objects.equals(id(), that.id());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id());
    }

    public static final class Identifiable<K, V extends TlsIdentifiable<K>> extends TlsProperty<V> {
        private static final Identifiable<Integer, TlsCipher> CIPHERS = new Identifiable<>("ciphers", true);
        private static final Identifiable<Byte, TlsCompression> COMPRESSIONS = new Identifiable<>("compressions", true);

        private Identifiable(String id, boolean negotiable) {
            super(id, negotiable);
        }
    }

    public static final class Value<V> extends TlsProperty<Boolean> {
        private static final Value<Boolean> EXTENDED_MASTER_SECRET = new Value<>("extendedMasterSecret", true);
        private static final Value<InetSocketAddress> REMOTE_ADDRESS = new Value<>("remoteAddress", false);

        private Value(String id, boolean negotiable) {
            super(id, negotiable);
        }
    }
}