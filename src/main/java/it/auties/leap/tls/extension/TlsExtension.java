package it.auties.leap.tls.extension;

import it.auties.leap.tls.certificate.TlsCertificateTrustedAuthorities;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsEcPointFormat;
import it.auties.leap.tls.extension.implementation.*;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.name.TlsName;
import it.auties.leap.tls.psk.TlsPskExchangeMode;
import it.auties.leap.tls.record.TlsMaxFragmentLength;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public sealed interface TlsExtension extends TlsExtensionMetadataProvider {

    // Pre-TLS 1.3 Extensions (or extensions behaving differently in 1.3)
    List<TlsVersion> RENEGOTIATION_INFO_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12); // RFC 5746 - Not used in TLS 1.3
    List<TlsVersion> SESSION_TICKET_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12); // RFC 5077 - Superseded by PSK mechanism in TLS 1.3
    List<TlsVersion> EXTENDED_MASTER_SECRET_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12); // RFC 7627 - Integrated into TLS 1.3, extension itself not used
    List<TlsVersion> ENCRYPT_THEN_MAC_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.DTLS10, TlsVersion.DTLS12); // RFC 7366 - Applies to DTLS too; Mandatory in TLS 1.3 (via AEAD), ext not used
    List<TlsVersion> EC_POINT_FORMATS_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12); // RFC 8422/4492 - Not used in TLS 1.3 (only uncompressed allowed)
    List<TlsVersion> HEARTBEAT_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.DTLS10, TlsVersion.DTLS12); // RFC 6520 - Applies to DTLS; Forbidden in TLS 1.3
    List<TlsVersion> SRP_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12); // RFC 5054 - Pre-TLS 1.3
    List<TlsVersion> NEXT_PROTOCOL_NEGOTIATION_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12); // Draft, largely unused/superseded by ALPN. Limiting to pre-1.3 seems reasonable.
    // --- Deprecated/Obsolete but maybe supported for legacy ---
    List<TlsVersion> CERT_TYPE_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12); // RFC 6091 (Obsolete by RFC 7250 for TLS 1.2+)
    List<TlsVersion> TRUNCATED_HMAC_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12); // RFC 6066 - Not used in TLS 1.3
    List<TlsVersion> CLIENT_CERTIFICATE_URL_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12); // RFC 6066
    List<TlsVersion> STATUS_REQUEST_V2_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 6961 - Multiple OCSP status requests. Applicable across versions.
    List<TlsVersion> USER_MAPPING_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 4681 - Seems generally applicable if needed.
    List<TlsVersion> CLIENT_AUTHZ_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 5878 - Seems generally applicable.
    List<TlsVersion> SERVER_AUTHZ_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 5878 - Seems generally applicable.
    List<TlsVersion> TRUSTED_CA_KEYS_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 6066 - Seems generally applicable.
    List<TlsVersion> TOKEN_BINDING_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 8472 - Applicable across versions.
    List<TlsVersion> CACHED_INFO_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 7924 - Seems generally applicable.
    List<TlsVersion> TLS_LTS_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // Draft - Assume general applicability if implemented.
    List<TlsVersion> TLMSP_DELEGATE_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // Experimental RFC 7633 - Assume general applicability.
    List<TlsVersion> TLMSP_PROXYING_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // Experimental RFC 7633 - Assume general applicability.
    List<TlsVersion> TLMSP_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // Experimental RFC 7633 - Assume general applicability.
    List<TlsVersion> SUPPORTED_EKT_CIPHERS_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 8870 - Used with DTLS-SRTP. Applicable across versions where SRTP is used.


    // Extensions introduced in TLS 1.2 and applicable forward
    List<TlsVersion> SIGNATURE_ALGORITHMS_VERSIONS = List.of(TlsVersion.TLS12, TlsVersion.TLS13, TlsVersion.DTLS12, TlsVersion.DTLS13); // RFC 5246 (TLS 1.2) / RFC 8446 (TLS 1.3)
    List<TlsVersion> SERVER_CERTIFICATE_TYPE_VERSIONS = List.of(TlsVersion.TLS12, TlsVersion.TLS13, TlsVersion.DTLS12, TlsVersion.DTLS13); // RFC 7250 (TLS 1.2+)
    List<TlsVersion> CLIENT_CERTIFICATE_TYPE_VERSIONS = List.of(TlsVersion.TLS12, TlsVersion.TLS13, TlsVersion.DTLS12, TlsVersion.DTLS13); // RFC 7250 (TLS 1.2+)
    List<TlsVersion> RECORD_SIZE_LIMIT_VERSIONS = List.of(TlsVersion.TLS12, TlsVersion.TLS13, TlsVersion.DTLS12, TlsVersion.DTLS13); // RFC 8449 (Defined for TLS 1.2/1.3, DTLS 1.2/1.3)

    // Extensions introduced in TLS 1.3 (or post-1.3 RFCs for 1.3)
    List<TlsVersion> KEY_SHARE_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> SUPPORTED_VERSIONS_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> PSK_KEY_EXCHANGE_MODES_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> PRE_SHARED_KEY_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> EARLY_DATA_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> COOKIE_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> POST_HANDSHAKE_AUTH_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> SIGNATURE_ALGORITHMS_CERT_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> CERTIFICATE_AUTHORITIES_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> OID_FILTERS_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8446
    List<TlsVersion> COMPRESS_CERTIFICATE_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8879 (for TLS 1.3)
    List<TlsVersion> DELEGATED_CREDENTIAL_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC Draft (for TLS 1.3)
    List<TlsVersion> ENCRYPTED_CLIENT_HELLO_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC Draft (targets TLS 1.3+)
    List<TlsVersion> ECH_OUTER_EXTENSIONS_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // Part of ECH Draft
    List<TlsVersion> QUIC_TRANSPORT_PARAMETERS_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 9001 (TLS 1.3 for QUIC)
    List<TlsVersion> TRANSPARENCY_INFO_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 9162 (Certificate Transparency v2 for TLS 1.3)
    List<TlsVersion> TICKET_REQUEST_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC draft-ietf-tls-ticketrequest
    List<TlsVersion> DNSSEC_CHAIN_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 9102 (Using DNS-Based Authentication of Named Entities (DANE) TLSA Records with TLS 1.3)
    List<TlsVersion> EXTERNAL_ID_HASH_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8773 - TLS 1.3 Resumption binder hash
    List<TlsVersion> EXTERNAL_SESSION_ID_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8773 - TLS 1.3 Resumption session id
    List<TlsVersion> TLS_FLAGS_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC draft-vvv-tls-flags
    List<TlsVersion> PWD_PROTECT_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8492 - TLS-PWD with TLS 1.3
    List<TlsVersion> PWD_CLEAR_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8492 - TLS-PWD with TLS 1.3
    List<TlsVersion> PASSWORD_SALT_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC 8492 - TLS-PWD with TLS 1.3
    List<TlsVersion> TICKET_PINNING_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC draft-friel-tls-ticket-pinning
    List<TlsVersion> TLS_CERT_WITH_EXTERN_PSK_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13); // RFC draft-ietf-tls-external-psk-importer

    // Generally applicable Extensions (defined pre-1.3, still relevant)
    List<TlsVersion> SERVER_NAME_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 6066 - SNI
    List<TlsVersion> MAX_FRAGMENT_LENGTH_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 6066
    List<TlsVersion> STATUS_REQUEST_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 6066 - OCSP Stapling
    List<TlsVersion> SUPPORTED_GROUPS_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 4492/8422/7919/8446 - Elliptic Curves/Groups
    List<TlsVersion> APPLICATION_LAYER_PROTOCOL_NEGOTIATION_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 7301 - ALPN
    List<TlsVersion> SIGNED_CERTIFICATE_TIMESTAMP_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 6962 - Cert Transparency v1
    List<TlsVersion> PADDING_VERSIONS = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13); // RFC 7685 / RFC 8446

    // DTLS Specific Extensions
    List<TlsVersion> USE_SRTP_VERSIONS = List.of(TlsVersion.DTLS10, TlsVersion.DTLS12, TlsVersion.DTLS13); // RFC 5764 / RFC 8870 (DTLS 1.0, 1.2, 1.3)
    List<TlsVersion> CONNECTION_ID_DEPRECATED_VERSIONS = List.of(TlsVersion.DTLS10, TlsVersion.DTLS12); // Draft - Likely intended for pre-RFC 9147 versions
    List<TlsVersion> CONNECTION_ID_VERSIONS = List.of(TlsVersion.DTLS12, TlsVersion.DTLS13); // RFC 9147 (DTLS 1.2, 1.3)
    List<TlsVersion> SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS_VERSIONS = List.of(TlsVersion.DTLS12, TlsVersion.DTLS13); // RFC 9146 (DTLS 1.2, 1.3)
    List<TlsVersion> RRC_VERSIONS = List.of(TlsVersion.DTLS12, TlsVersion.DTLS13); // RFC 9146 (DTLS 1.2, 1.3) Record Replay Protection

    // Misc
    List<TlsVersion> GREASE_VERSIONS = List.of(TlsVersion.TLS12, TlsVersion.TLS13, TlsVersion.DTLS12, TlsVersion.DTLS13); // RFC 8701 - Primarily relevant where extension negotiation is complex (TLS 1.2+)

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

    static Configured.Agnostic extendedMasterSecret() {
        return ExtendedMasterSecretExtension.instance();
    }

    static Configured.Agnostic encryptThenMac() {
        return EncryptThenMacExtension.instance();
    }

    static Configured.Agnostic postHandshakeAuth() {
        return PostHandshakeAuthExtension.instance();
    }

    static Configured.Client nextProtocolNegotiation() {
        return NPNClientExtension.instance();
    }

    static Configured.Server nextProtocolNegotiation(String selectedProtocol) {
        return new NPNServerExtension(selectedProtocol);
    }

    static Configurable serverNameIndication(TlsName.Type nameType) {
        return new ServerNameExtension(nameType);
    }

    static Configurable supportedVersions() {
        return SupportedVersionsExtension.instance();
    }

    static Configured.Agnostic alpn(List<String> supportedProtocols) {
        return new ALPNExtension(supportedProtocols);
    }

    static Configured.Agnostic padding(int targetLength) {
        return new PaddingExtension(targetLength);
    }

    static Configured.Agnostic ecPointFormats() {
        return ECPointFormatExtension.all();
    }

    static Configured.Agnostic ecPointFormats(List<TlsEcPointFormat> formats) {
        return new ECPointFormatExtension(formats);
    }

    static Configured.Agnostic supportedGroups() {
        return SupportedGroupsExtension.recommended();
    }

    static Configured.Agnostic supportedGroups(List<TlsSupportedGroup> groups) {
        return new SupportedGroupsExtension(groups);
    }

    static Configured.Agnostic signatureAlgorithms() {
        return SignatureAlgorithmsExtension.recommended();
    }

    static Configured.Agnostic signatureAlgorithms(List<TlsSignature> algorithms) {
        return new SignatureAlgorithmsExtension(algorithms);
    }

    static Configured.Agnostic pskExchangeModes(List<TlsPskExchangeMode> modes) {
        return new PSKExchangeModesExtension(modes);
    }

    static Configured.Agnostic maxFragmentLength(TlsMaxFragmentLength maxFragmentLength) {
        return new MaxFragmentLengthExtension(maxFragmentLength);
    }

    static Configured.Agnostic clientCertificateUrl() {
        return ClientCertificateUrlExtension.instance();
    }

    static Configured.Client trustedCAKeys(TlsCertificateTrustedAuthorities trustedAuthorities) {
        return new TrustedCAKeysClientExtension(trustedAuthorities);
    }

    static Configured.Server trustedCAKeys() {
        return TrustedCAKeysServerExtension.instance();
    }

    static Configured.Server truncatedHmac() {
        return TruncatedHmacExtension.instance();
    }

    static Configured.Server userMapping() {
        return TruncatedHmacExtension.instance();
    }


    static Configurable keyShare() {
        return KeyShareExtension.instance();
    }

    static Configured.Agnostic grease(int type, byte[] data) {
        return new GREASEExtension(type, data);
    }

    static Configured.Agnostic grease(int type) {
        return new GREASEExtension(type, null);
    }

    sealed interface Configured extends TlsExtension, TlsExtensionState.Configured {
        non-sealed interface Client extends TlsExtension.Configured, TlsExtensionOwner.Client {
            Optional<? extends TlsExtension.Configured.Server> deserialize(TlsContext context, int type, ByteBuffer response);
        }

        non-sealed interface Server extends TlsExtension.Configured, TlsExtensionOwner.Server {
            Optional<? extends TlsExtension.Configured.Client> deserialize(TlsContext context, int type, ByteBuffer response);
        }

        non-sealed interface Agnostic extends Client, Server, TlsExtension.Configured  {
            Optional<? extends TlsExtension.Configured.Agnostic> deserialize(TlsContext context, int type, ByteBuffer response);
        }
    }

    // Configurable is intrinsically agnostic
    non-sealed interface Configurable extends TlsExtension, TlsExtensionOwner.Client, TlsExtensionOwner.Server, TlsExtensionState.Configurable {

    }
}
