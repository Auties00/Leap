package it.auties.leap.tls.context;

import it.auties.leap.tls.certificate.TlsCertificateCompressionAlgorithm;
import it.auties.leap.tls.certificate.TlsCertificateTrustedAuthority;
import it.auties.leap.tls.ciphersuite.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.ec.TlsEcPointFormat;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.psk.TlsPskExchangeMode;
import it.auties.leap.tls.record.TlsMaxFragmentLength;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.supplemental.TlsUserMappingDataDeserializer;
import it.auties.leap.tls.version.TlsVersion;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

@SuppressWarnings("unused")
public final class TlsContextualProperty<I, O> {
    private static final TlsContextualProperty<List<TlsVersion>, TlsVersion> VERSION = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<TlsCipherSuite>, TlsCipherSuite> CIPHER = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<TlsCompression>, TlsCompression> COMPRESSION = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<TlsSupportedGroup>, List<TlsSupportedGroup>> SUPPORTED_GROUPS = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<TlsEcPointFormat>, List<TlsEcPointFormat>> EC_POINTS_FORMATS = new TlsContextualProperty<>();
    private static final TlsContextualProperty<Boolean, Boolean> EXTENDED_MASTER_SECRET = new TlsContextualProperty<>();
    private static final TlsContextualProperty<Boolean, Boolean> ENCRYPT_THEN_MAC = new TlsContextualProperty<>();
    private static final TlsContextualProperty<Boolean, Boolean> POST_HANDSHAKE_AUTH = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<String>, List<String>> APPLICATION_PROTOCOLS = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<TlsPskExchangeMode>, List<TlsPskExchangeMode>> PSK_EXCHANGE_MODES = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<TlsSignature>, List<TlsSignature>> SIGNATURE_ALGORITHMS = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<TlsCertificateCompressionAlgorithm>, List<TlsCertificateCompressionAlgorithm>> CERTIFICATE_COMPRESSION_ALGORITHMS = new TlsContextualProperty<>();
    private static final TlsContextualProperty<TlsMaxFragmentLength, TlsMaxFragmentLength> MAX_FRAGMENT_LENGTH = new TlsContextualProperty<>();
    private static final TlsContextualProperty<Boolean, Boolean> CERTIFICATE_URLS = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<TlsCertificateTrustedAuthority>, List<TlsCertificateTrustedAuthority>> TRUSTED_CA = new TlsContextualProperty<>();
    private static final TlsContextualProperty<Boolean, Boolean> TRUNCATED_HMAC = new TlsContextualProperty<>();
    private static final TlsContextualProperty<List<TlsUserMappingDataDeserializer>, List<TlsUserMappingDataDeserializer>> USER_MAPPINGS = new TlsContextualProperty<>();

    private final UUID id;

    private TlsContextualProperty() {
        this.id = UUID.randomUUID();
    }

    public static <K, V> TlsContextualProperty<K, V> of() {
        return new TlsContextualProperty<>();
    }

    public static TlsContextualProperty<List<TlsVersion>, TlsVersion> version() {
        return VERSION;
    }

    public static TlsContextualProperty<List<TlsCipherSuite>, TlsCipherSuite> cipher() {
        return CIPHER;
    }

    public static TlsContextualProperty<List<TlsCompression>, TlsCompression> compression() {
        return COMPRESSION;
    }

    public static TlsContextualProperty<Boolean, Boolean> extendedMasterSecret() {
        return EXTENDED_MASTER_SECRET;
    }

    public static TlsContextualProperty<Boolean, Boolean> encryptThenMac() {
        return ENCRYPT_THEN_MAC;
    }

    public static TlsContextualProperty<Boolean, Boolean> postHandshakeAuth() {
        return POST_HANDSHAKE_AUTH;
    }

    public static TlsContextualProperty<List<String>, List<String>> applicationProtocols() {
        return APPLICATION_PROTOCOLS;
    }

    public static TlsContextualProperty<List<TlsSupportedGroup>, List<TlsSupportedGroup>> supportedGroups() {
        return SUPPORTED_GROUPS;
    }

    public static TlsContextualProperty<List<TlsEcPointFormat>, List<TlsEcPointFormat>> ecPointsFormats() {
        return EC_POINTS_FORMATS;
    }

    public static TlsContextualProperty<List<TlsPskExchangeMode>, List<TlsPskExchangeMode>> pskExchangeModes() {
        return PSK_EXCHANGE_MODES;
    }

    public static TlsContextualProperty<List<TlsSignature>, List<TlsSignature>> signatureAlgorithms() {
        return SIGNATURE_ALGORITHMS;
    }

    public static TlsContextualProperty<List<TlsCertificateCompressionAlgorithm>, List<TlsCertificateCompressionAlgorithm>> certificateCompressionAlgorithms() {
        return CERTIFICATE_COMPRESSION_ALGORITHMS;
    }

    public static TlsContextualProperty<TlsMaxFragmentLength, TlsMaxFragmentLength> maxFragmentLength() {
        return MAX_FRAGMENT_LENGTH;
    }

    public static TlsContextualProperty<Boolean, Boolean> certificateUrls() {
        return CERTIFICATE_URLS;
    }

    public static TlsContextualProperty<List<TlsCertificateTrustedAuthority>, List<TlsCertificateTrustedAuthority>> trustedCA() {
        return TRUSTED_CA;
    }

    public static TlsContextualProperty<Boolean, Boolean> truncatedHmac() {
        return TRUNCATED_HMAC;
    }

    public static TlsContextualProperty<List<TlsUserMappingDataDeserializer>, List<TlsUserMappingDataDeserializer>> userMappings() {
        return USER_MAPPINGS;
    }

    public UUID id() {
        return id;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsContextualProperty<?, ?> that
                && Objects.equals(id(), that.id());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id());
    }
}