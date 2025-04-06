package it.auties.leap.tls.property;

import it.auties.leap.tls.certificate.TlsCertificateCompressionAlgorithm;
import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.ec.TlsECPointFormat;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.version.TlsVersion;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

@SuppressWarnings("unused")
public final class TlsProperty<I, O> implements TlsIdentifiableProperty<UUID> {
    private static final TlsProperty<List<TlsVersion>, TlsVersion> VERSION = new TlsProperty<>();
    private static final TlsProperty<List<? extends TlsExtensionOwner.Client>, List<? extends TlsExtension.Configured.Client>> CLIENT_EXTENSIONS = new TlsProperty<>();
    private static final TlsProperty<List<? extends TlsExtensionOwner.Server>, List<? extends TlsExtension.Configured.Server>> SERVER_EXTENSIONS = new TlsProperty<>();
    private static final TlsProperty<List<TlsCipherSuite>, TlsCipherSuite> CIPHER = new TlsProperty<>();
    private static final TlsProperty<List<TlsCompression>, TlsCompression> COMPRESSION = new TlsProperty<>();
    private static final TlsProperty<List<TlsSupportedGroup>, List<TlsSupportedGroup>> SUPPORTED_GROUPS = new TlsProperty<>();
    private static final TlsProperty<List<TlsECPointFormat>, List<TlsECPointFormat>> EC_POINTS_FORMATS = new TlsProperty<>();
    private static final TlsProperty<Boolean, Boolean> EXTENDED_MASTER_SECRET = new TlsProperty<>();
    private static final TlsProperty<Boolean, Boolean> ENCRYPT_THEN_MAC = new TlsProperty<>();
    private static final TlsProperty<Boolean, Boolean> POST_HANDSHAKE_AUTH = new TlsProperty<>();
    private static final TlsProperty<List<String>, List<String>> APPLICATION_PROTOCOLS = new TlsProperty<>();
    private static final TlsProperty<List<TlsPSKExchangeMode>, List<TlsPSKExchangeMode>> PSK_EXCHANGE_MODES = new TlsProperty<>();
    private static final TlsProperty<List<TlsSignature>, List<TlsSignature>> SIGNATURE_ALGORITHMS = new TlsProperty<>();
    private static final TlsProperty<List<TlsCertificateCompressionAlgorithm>, List<TlsCertificateCompressionAlgorithm>> CERTIFICATE_COMPRESSION_ALGORITHMS = new TlsProperty<>();

    private final UUID id;

    private TlsProperty() {
        this.id = UUID.randomUUID();
    }

    public static <K, V> TlsProperty<K, V> newTlsProperty() {
        return new TlsProperty<>();
    }

    public static TlsProperty<List<TlsVersion>, TlsVersion> version() {
        return VERSION;
    }

    public static TlsProperty<List<? extends TlsExtensionOwner.Client>, List<? extends TlsExtension.Configured.Client>> clientExtensions() {
        return CLIENT_EXTENSIONS;
    }

    public static TlsProperty<List<? extends TlsExtensionOwner.Server>, List<? extends TlsExtension.Configured.Server>> serverExtensions() {
        return SERVER_EXTENSIONS;
    }

    public static TlsProperty<List<TlsCipherSuite>, TlsCipherSuite> cipher() {
        return CIPHER;
    }

    public static TlsProperty<List<TlsCompression>, TlsCompression> compression() {
        return COMPRESSION;
    }

    public static TlsProperty<Boolean, Boolean> extendedMasterSecret() {
        return EXTENDED_MASTER_SECRET;
    }

    public static TlsProperty<Boolean, Boolean> encryptThenMac() {
        return ENCRYPT_THEN_MAC;
    }

    public static TlsProperty<Boolean, Boolean> postHandshakeAuth() {
        return POST_HANDSHAKE_AUTH;
    }

    public static TlsProperty<List<String>, List<String>> applicationProtocols() {
        return APPLICATION_PROTOCOLS;
    }

    public static TlsProperty<List<TlsSupportedGroup>, List<TlsSupportedGroup>> supportedGroups() {
        return SUPPORTED_GROUPS;
    }

    public static TlsProperty<List<TlsECPointFormat>, List<TlsECPointFormat>> ecPointsFormats() {
        return EC_POINTS_FORMATS;
    }

    public static TlsProperty<List<TlsPSKExchangeMode>, List<TlsPSKExchangeMode>> pskExchangeModes() {
        return PSK_EXCHANGE_MODES;
    }

    public static TlsProperty<List<TlsSignature>, List<TlsSignature>> signatureAlgorithms() {
        return SIGNATURE_ALGORITHMS;
    }

    public static TlsProperty<List<TlsCertificateCompressionAlgorithm>, List<TlsCertificateCompressionAlgorithm>> certificateCompressionAlgorithms() {
        return CERTIFICATE_COMPRESSION_ALGORITHMS;
    }

    @Override
    public UUID id() {
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