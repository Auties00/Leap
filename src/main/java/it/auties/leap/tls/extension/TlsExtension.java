package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.implementation.*;
import it.auties.leap.tls.ec.TlsECPointFormat;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsExtension {
    List<TlsVersion> TLS_UNTIL_12 = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12);
    List<TlsVersion> TLS_UNTIL_13 = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13);
    List<TlsVersion> DTLS_UNTIL_12 = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.DTLS10, TlsVersion.DTLS12);
    List<TlsVersion> DTLS_UNTIL_13 = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13, TlsVersion.DTLS10, TlsVersion.DTLS12, TlsVersion.DTLS13);

    List<TlsVersion> RENEGOTIATION_INFO_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> TLMSP_DELEGATE_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> TLMSP_PROXYING_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> TLMSP_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> SESSION_TICKET_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> TLS_LTS_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> CACHED_INFO_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> TOKEN_BINDING_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> EXTENDED_MASTER_SECRET_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> ENCRYPT_THEN_MAC_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> STATUS_REQUEST_V2_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> SRP_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> EC_POINT_FORMATS_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> CERT_TYPE_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> SERVER_AUTHZ_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> CLIENT_AUTHZ_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> USER_MAPPING_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> TRUNCATED_HMAC_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> TRUSTED_CA_KEYS_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> CLIENT_CERTIFICATE_URL_VERSIONS = TLS_UNTIL_12;
    List<TlsVersion> ENCRYPTED_CLIENT_HELLO_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> ECH_OUTER_EXTENSIONS_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> NEXT_PROTOCOL_NEGOTIATION_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> TLS_FLAGS_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> DNSSEC_CHAIN_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> TICKET_REQUEST_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> QUIC_TRANSPORT_PARAMETERS_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> EXTERNAL_SESSION_ID_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> EXTERNAL_ID_HASH_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> TRANSPARENCY_INFO_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> KEY_SHARE_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> SIGNATURE_ALGORITHMS_CERT_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> POST_HANDSHAKE_AUTH_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> OID_FILTERS_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> CERTIFICATE_AUTHORITIES_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> PSK_KEY_EXCHANGE_MODES_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> COOKIE_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> SUPPORTED_VERSIONS_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> EARLY_DATA_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> PRE_SHARED_KEY_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> SUPPORTED_EKT_CIPHERS_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> DELEGATED_CREDENTIAL_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> TLS_CERT_WITH_EXTERN_PSK_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> TICKET_PINNING_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> PASSWORD_SALT_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> PWD_CLEAR_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> PWD_PROTECT_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> RECORD_SIZE_LIMIT_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> COMPRESS_CERTIFICATE_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> PADDING_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> SERVER_CERTIFICATE_TYPE_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> CLIENT_CERTIFICATE_TYPE_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> SIGNED_CERTIFICATE_TIMESTAMP_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> APPLICATION_LAYER_PROTOCOL_NEGOTIATION_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> HEARTBEAT_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> USE_SRTP_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> SIGNATURE_ALGORITHMS_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> SUPPORTED_GROUPS_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> STATUS_REQUEST_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> MAX_FRAGMENT_LENGTH_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> SERVER_NAME_VERSIONS = TLS_UNTIL_13;
    List<TlsVersion> CONNECTION_ID_DEPRECATED_VERSIONS = DTLS_UNTIL_12;
    List<TlsVersion> RRC_VERSIONS = DTLS_UNTIL_13;
    List<TlsVersion> SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS_VERSIONS = DTLS_UNTIL_13;
    List<TlsVersion> CONNECTION_ID_VERSIONS = DTLS_UNTIL_13;
    List<TlsVersion> GREASE_VERSIONS = List.of(TlsVersion.TLS12, TlsVersion.TLS13);


    int SERVER_NAME_TYPE = 0;
    int MAX_FRAGMENT_LENGTH_TYPE = 1;
    int CLIENT_CERTIFICATE_URL_TYPE = 2;
    int TRUSTED_CA_KEYS_TYPE = 3;
    int TRUNCATED_HMAC_TYPE = 4;
    int STATUS_REQUEST_TYPE = 5;
    int USER_MAPPING_TYPE = 6;
    int CLIENT_AUTHZ_TYPE = 7;
    int SERVER_AUTHZ_TYPE = 8;
    int CERT_TYPE_TYPE = 9;
    int SUPPORTED_GROUPS_TYPE = 10;
    int EC_POINT_FORMATS_TYPE = 11;
    int SRP_TYPE = 12;
    int SIGNATURE_ALGORITHMS_TYPE = 13;
    int USE_SRTP_TYPE = 14;
    int HEARTBEAT_TYPE = 15;
    int APPLICATION_LAYER_PROTOCOL_NEGOTIATION_TYPE = 16;
    int STATUS_REQUEST_V2_TYPE = 17;
    int SIGNED_CERTIFICATE_TIMESTAMP_TYPE = 18;
    int CLIENT_CERTIFICATE_TYPE_TYPE = 19;
    int SERVER_CERTIFICATE_TYPE_TYPE = 20;
    int PADDING_TYPE = 21;
    int ENCRYPT_THEN_MAC_TYPE = 22;
    int EXTENDED_MASTER_SECRET_TYPE = 23;
    int TOKEN_BINDING_TYPE = 24;
    int CACHED_INFO_TYPE = 25;
    int TLS_LTS_TYPE = 26;
    int COMPRESS_CERTIFICATE_TYPE = 27;
    int RECORD_SIZE_LIMIT_TYPE = 28;
    int PWD_PROTECT_TYPE = 29;
    int PWD_CLEAR_TYPE = 30;
    int PASSWORD_SALT_TYPE = 31;
    int TICKET_PINNING_TYPE = 32;
    int TLS_CERT_WITH_EXTERN_PSK_TYPE = 33;
    int DELEGATED_CREDENTIAL_TYPE = 34;
    int SESSION_TICKET_TYPE = 35;
    int TLMSP_TYPE = 36;
    int TLMSP_PROXYING_TYPE = 37;
    int TLMSP_DELEGATE_TYPE = 38;
    int SUPPORTED_EKT_CIPHERS_TYPE = 39;
    int PRE_SHARED_KEY_TYPE = 41;
    int EARLY_DATA_TYPE = 42;
    int SUPPORTED_VERSIONS_TYPE = 43;
    int COOKIE_TYPE = 44;
    int PSK_KEY_EXCHANGE_MODES_TYPE = 45;
    int CERTIFICATE_AUTHORITIES_TYPE = 47;
    int OID_FILTERS_TYPE = 48;
    int POST_HANDSHAKE_AUTH_TYPE = 49;
    int SIGNATURE_ALGORITHMS_CERT_TYPE = 50;
    int KEY_SHARE_TYPE = 51;
    int TRANSPARENCY_INFO_TYPE = 52;
    int CONNECTION_ID_DEPRECATED_TYPE = 53;
    int CONNECTION_ID_TYPE = 54;
    int EXTERNAL_ID_HASH_TYPE = 55;
    int EXTERNAL_SESSION_ID_TYPE = 56;
    int QUIC_TRANSPORT_PARAMETERS_TYPE = 57;
    int TICKET_REQUEST_TYPE = 58;
    int DNSSEC_CHAIN_TYPE = 59;
    int SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS_TYPE = 60;
    int RRC_TYPE = 61;
    int TLS_FLAGS_TYPE = 62;
    int NEXT_PROTOCOL_NEGOTIATION_TYPE = 0x3374;
    int ECH_OUTER_EXTENSIONS_TYPE = 64768;
    int ENCRYPTED_CLIENT_HELLO_TYPE = 65037;
    int RENEGOTIATION_INFO_TYPE = 65281;

    static TlsExtension extendedMasterSecret() {
        return ExtendedMasterSecretExtension.Configurable.instance();
    }

    static TlsExtension encryptThenMac() {
        return EncryptThenMacExtension.instance();
    }

    static TlsExtension postHandshakeAuth() {
        return PostHandshakeAuthExtension.instance();
    }

    static TlsExtension nextProtocolNegotiation() {
        return NPNExtension.Client.instance();
    }

    static TlsExtension serverNameIndication() {
        return SNIExtension.Configurable.instance();
    }

    static TlsExtension supportedVersions() {
        return SupportedVersionsExtension.Client.Configurable.instance();
    }

    static TlsExtension supportedVersions(List<TlsVersionId> tlsVersions) {
        return new SupportedVersionsExtension.Client.Concrete(tlsVersions);
    }

    static TlsExtension alpn(List<String> supportedProtocols) {
        return ALPNExtension.of(supportedProtocols);
    }

    static TlsExtension padding(int targetLength) {
        return new PaddingExtension.Configurable(targetLength);
    }

    static TlsExtension ecPointFormats() {
        return ECPointFormatExtension.all();
    }

    static TlsExtension ecPointFormats(List<TlsECPointFormat> formats) {
        return ECPointFormatExtension.of(formats);
    }

    static TlsExtension supportedGroups() {
        return SupportedGroupsExtension.Configurable.recommended();
    }

    static TlsExtension supportedGroups(List<TlsSupportedGroup> groups) {
        return new SupportedGroupsExtension.Configurable(groups);
    }

    static TlsExtension signatureAlgorithms() {
        return SignatureAlgorithmsExtension.recommended();
    }

    static TlsExtension signatureAlgorithms(List<TlsSignature> algorithms) {
        return SignatureAlgorithmsExtension.of(algorithms);
    }

    static TlsExtension pskExchangeModes(List<TlsPSKExchangeMode> modes) {
        return PSKExchangeModesExtension.of(modes);
    }

    static TlsExtension keyShare() {
        return KeyShareExtension.Configurable.instance();
    }

    static List<TlsExtension> required(List<TlsVersion> versions) {
        if(!versions.contains(TlsVersion.TLS13) && !versions.contains(TlsVersion.DTLS13)) {
            return List.of();
        }

        return List.of(supportedVersions(), keyShare(), signatureAlgorithms());
    }

    int extensionType();

    List<TlsVersion> versions();

    TlsExtensionDeserializer decoder();

    non-sealed interface Concrete extends TlsExtension {
        void apply(TlsContext context, TlsSource source);

        default void serializeExtension(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, extensionType());
            writeBigEndianInt16(buffer, extensionPayloadLength());
            serializeExtensionPayload(buffer);
        }

        default int extensionLength() {
            return INT16_LENGTH + INT16_LENGTH + extensionPayloadLength();
        }

        void serializeExtensionPayload(ByteBuffer buffer);

        int extensionPayloadLength();
    }

    non-sealed interface Configurable extends TlsExtension {
        Optional<? extends Concrete> newInstance(TlsContext context);

        Dependencies dependencies();

        sealed interface Dependencies {
            static None none() {
                return None.INSTANCE;
            }

            static Some some(Integer... includedTypes) {
                return new Some(Set.of(includedTypes));
            }

            static All all() {
                return All.INSTANCE;
            }

            final class None implements Dependencies {
                private static final None INSTANCE = new None();

                private None() {

                }
            }

            final class Some implements Dependencies {
                private final Set<Integer> includedTypes;

                private Some(Set<Integer> includedTypes) {
                    this.includedTypes = includedTypes;
                }

                public Set<Integer> includedTypes() {
                    return includedTypes;
                }
            }

            final class All implements Dependencies {
                private static final All INSTANCE = new All();

                private All() {

                }
            }
        }
    }
}
