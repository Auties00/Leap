package it.auties.leap.tls.property;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.ec.TlsECPointFormat;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.version.TlsVersion;

import java.util.List;
import java.util.Objects;

@SuppressWarnings("unused")
public final class TlsProperty<I, O> implements TlsIdentifiableProperty<String> {
    private static final TlsProperty<List<TlsVersion>, TlsVersion> VERSION = new TlsProperty<>("version");
    private static final TlsProperty<List<TlsExtension>, List<TlsExtension.Concrete>> EXTENSIONS = new TlsProperty<>("extensions");
    private static final TlsProperty<List<TlsCipher>, TlsCipher> CIPHER = new TlsProperty<>("cipher");
    private static final TlsProperty<List<TlsCompression>, TlsCompression> COMPRESSION = new TlsProperty<>("compression");
    private static final TlsProperty<List<TlsSupportedGroup>, List<TlsSupportedGroup>> SUPPORTED_GROUPS = new TlsProperty<>("supportedGroups");
    private static final TlsProperty<List<TlsECPointFormat>, List<TlsECPointFormat>> EC_POINTS_FORMATS = new TlsProperty<>("ecPointsFormat");
    private static final TlsProperty<Boolean, Boolean> EXTENDED_MASTER_SECRET = new TlsProperty<>("extendedMasterSecret");

    public static <K, V extends TlsIdentifiableProperty<K>> TlsProperty<K, V> of(String key) {
        return new TlsProperty<>(key);
    }

    public static TlsProperty<List<TlsVersion>, TlsVersion> version() {
        return VERSION;
    }

    public static TlsProperty<List<TlsExtension>, List<TlsExtension.Concrete>> extensions() {
        return EXTENSIONS;
    }

    public static TlsProperty<List<TlsCipher>, TlsCipher> cipher() {
        return CIPHER;
    }

    public static TlsProperty<List<TlsCompression>, TlsCompression> compression() {
        return COMPRESSION;
    }

    public static TlsProperty<Boolean, Boolean> extendedMasterSecret() {
        return EXTENDED_MASTER_SECRET;
    }

    public static TlsProperty<List<TlsSupportedGroup>, List<TlsSupportedGroup>> supportedGroups() {
        return SUPPORTED_GROUPS;
    }

    public static TlsProperty<List<TlsECPointFormat>, List<TlsECPointFormat>> ecPointsFormats() {
        return EC_POINTS_FORMATS;
    }

    final String id;

    private TlsProperty(String id) {
        this.id = id;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsProperty<?, ?> that
                && Objects.equals(id(), that.id());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id());
    }
}