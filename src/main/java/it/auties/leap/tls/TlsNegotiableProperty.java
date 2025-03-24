package it.auties.leap.tls;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;

import java.net.InetSocketAddress;
import java.util.Objects;

@SuppressWarnings("unused")
public sealed abstract class TlsNegotiableProperty<I, O> {
    public static Identifiable.Singleton<Integer, TlsCipher> ciphers() {
        return Identifiable.Singleton.CIPHERS;
    }

    public static Identifiable.Singleton<Byte, TlsCompression> compressions() {
        return Identifiable.Singleton.COMPRESSIONS;
    }

    public static Value<Boolean> extendedMasterSecret() {
        return Value.EXTENDED_MASTER_SECRET;
    }

    public static Value<InetSocketAddress> remoteAddress() {
        return Value.REMOTE_ADDRESS;
    }

    public static <K, V extends TlsIdentifiable<K>> Identifiable.Singleton<K, V> identifiableSingleton(String key, boolean negotiable) {
        return new Identifiable.Singleton<>(key, negotiable);
    }

    public static <K, V extends TlsIdentifiable<K>> Identifiable.List<K, V> identifiableList(String key, boolean negotiable) {
        return new Identifiable.List<>(key, negotiable);
    }

    public static <V> Value<V> value(String key, boolean negotiable) {
        return new Value<>(key, negotiable);
    }

    final String id;
    final boolean negotiable;
    private TlsNegotiableProperty(String id, boolean negotiable) {
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
        return o instanceof TlsNegotiableProperty<?, ?> that
                && Objects.equals(id(), that.id());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id());
    }

    public static sealed abstract class Identifiable<K, I extends TlsIdentifiable<K>, O> extends TlsNegotiableProperty<I, O> {
        private Identifiable(String id, boolean negotiable) {
            super(id, negotiable);
        }

        public static final class Singleton<K, I extends TlsIdentifiable<K>> extends Identifiable<K, I, I> {
            private static final Singleton<Integer, TlsCipher> CIPHERS = new Singleton<>("ciphers", true);
            private static final Singleton<Byte, TlsCompression> COMPRESSIONS = new Singleton<>("compressions", true);

            private Singleton(String id, boolean negotiable) {
                super(id, negotiable);
            }
        }

        public static final class List<K, I extends TlsIdentifiable<K>> extends Identifiable<K, I, java.util.List<I>> {
            private List(String id, boolean negotiable) {
                super(id, negotiable);
            }
        }
    }

    public static final class Value<V> extends TlsNegotiableProperty<V, V> {
        private static final Value<Boolean> EXTENDED_MASTER_SECRET = new Value<>("extendedMasterSecret", true);
        private static final Value<InetSocketAddress> REMOTE_ADDRESS = new Value<>("remoteAddress", false);

        private Value(String id, boolean negotiable) {
            super(id, negotiable);
        }
    }
}