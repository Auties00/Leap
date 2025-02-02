package it.auties.leap.tls.extension;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.extension.implementation.*;
import it.auties.leap.tls.ec.TlsECPointFormat;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;
import it.auties.leap.tls.key.TlsSupportedGroup;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeLittleEndianInt16;

public sealed interface TlsExtension {
    List<TlsVersion> RENEGOTIATION_INFO_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // TLMSP is not an IETF-standard extension, so usage is unclear.
// Assume it might be permitted on all versions if you support it.
    List<TlsVersion> TLMSP_DELEGATE_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );
    List<TlsVersion> TLMSP_PROXYING_VERSIONS = TLMSP_DELEGATE_VERSIONS;
    List<TlsVersion> TLMSP_VERSIONS = TLMSP_DELEGATE_VERSIONS;

    // SessionTicket TLS (RFC 5077) is used in TLS <=1.2 and DTLS <=1.2.
// TLS 1.3 does session tickets differently and does not negotiate
// the "session_ticket" extension in ClientHello.
    List<TlsVersion> SESSION_TICKET_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // "TLS_LTS" is a non-standard "long-term support" draft. Typically
// used with TLS 1.2 and earlier. Adjust if you support it on 1.3.
    List<TlsVersion> TLS_LTS_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // cached_info (RFC 7924) was written for TLS <=1.2 and DTLS <=1.2.
    List<TlsVersion> CACHED_INFO_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // Token Binding (RFC 8472 / 8473) was defined for TLS <=1.2 and DTLS <=1.2.
    List<TlsVersion> TOKEN_BINDING_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // Extended Master Secret (RFC 7627) applies to TLS <=1.2 and DTLS <=1.2.
    List<TlsVersion> EXTENDED_MASTER_SECRET_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // Encrypt-then-MAC (RFC 7366) also applies to TLS <=1.2 and DTLS <=1.2.
    List<TlsVersion> ENCRYPT_THEN_MAC_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // status_request_v2 (RFC 6961) was introduced for TLS <=1.2 and DTLS <=1.2.
    List<TlsVersion> STATUS_REQUEST_V2_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // SRP (RFC 5054) also only standardized for TLS <=1.2 and DTLS <=1.2.
    List<TlsVersion> SRP_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // ec_point_formats (RFC 4492) used up to TLS 1.2/DTLS 1.2; not in TLS 1.3.
    List<TlsVersion> EC_POINT_FORMATS_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // cert_type (RFC 7250) is generally for TLS <=1.2/DTLS <=1.2 (though some
// implementations may try to use it in 1.3).
    List<TlsVersion> CERT_TYPE_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // server_authz / client_authz / user_mapping are non-standard or older
// proposals. Typically only used with TLS <=1.2, DTLS <=1.2.
    List<TlsVersion> SERVER_AUTHZ_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );
    List<TlsVersion> CLIENT_AUTHZ_VERSIONS = SERVER_AUTHZ_VERSIONS;
    List<TlsVersion> USER_MAPPING_VERSIONS = SERVER_AUTHZ_VERSIONS;

    // truncated_hmac (RFC 6066) is only for TLS <=1.2 and DTLS <=1.2.
    List<TlsVersion> TRUNCATED_HMAC_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // trusted_ca_keys / client_certificate_url were old proposals
// or rarely used. Typically only in TLS <=1.2, DTLS <=1.2.
    List<TlsVersion> TRUSTED_CA_KEYS_VERSIONS = SERVER_AUTHZ_VERSIONS;
    List<TlsVersion> CLIENT_CERTIFICATE_URL_VERSIONS = SERVER_AUTHZ_VERSIONS;

    // Encrypted ClientHello (ECH), formerly "Encrypted SNI," is only for
// TLS 1.3+ (and possibly DTLS 1.3).
    List<TlsVersion> ENCRYPTED_CLIENT_HELLO_VERSIONS = List.of(
            TlsVersion.TLS13,
            TlsVersion.DTLS13
    );
    List<TlsVersion> ECH_OUTER_EXTENSIONS_VERSIONS = ENCRYPTED_CLIENT_HELLO_VERSIONS;

    // Next Protocol Negotiation (NPN) was a non-standard extension
// used mostly in TLS <=1.2 (no TLS 1.3 support).
    List<TlsVersion> NEXT_PROTOCOL_NEGOTIATION_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // "TLS_FLAGS" not an official extension; assume it might be used everywhere:
    List<TlsVersion> TLS_FLAGS_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // DNSSEC_CHAIN is a custom extension.  Usage is unclear; assume all:
    List<TlsVersion> DNSSEC_CHAIN_VERSIONS = TLS_FLAGS_VERSIONS;

    // ticket_request (draft-ietf-tls-ticketrequests) is specifically
// for TLS 1.3+ to request multiple session tickets.
    List<TlsVersion> TICKET_REQUEST_VERSIONS = List.of(
            TlsVersion.TLS13,
            TlsVersion.DTLS13
    );

    // QUIC transport parameters are only valid in the TLS 1.3 handshake for QUIC.
// (DTLS 1.3 is not used by QUIC, but if you have an implementation, adjust.)
    List<TlsVersion> QUIC_TRANSPORT_PARAMETERS_VERSIONS = List.of(
            TlsVersion.TLS13
    );

    // external_session_id / external_id_hash / transparency_info are
// likely custom/draft.  Adjust as needed.  Shown here for TLS 1.3 only:
    List<TlsVersion> EXTERNAL_SESSION_ID_VERSIONS = List.of(TlsVersion.TLS13, TlsVersion.DTLS13);
    List<TlsVersion> EXTERNAL_ID_HASH_VERSIONS = EXTERNAL_SESSION_ID_VERSIONS;
    List<TlsVersion> TRANSPARENCY_INFO_VERSIONS = EXTERNAL_SESSION_ID_VERSIONS;

    // key_share (RFC 8446) is for TLS 1.3 key exchange (and DTLS 1.3).
    List<TlsVersion> KEY_SHARE_VERSIONS = List.of(
            TlsVersion.TLS13,
            TlsVersion.DTLS13
    );
    // signature_algorithms_cert (RFC 8446) also TLS 1.3+.
    List<TlsVersion> SIGNATURE_ALGORITHMS_CERT_VERSIONS = KEY_SHARE_VERSIONS;
    // post_handshake_auth (RFC 8446) TLS 1.3+.
    List<TlsVersion> POST_HANDSHAKE_AUTH_VERSIONS = KEY_SHARE_VERSIONS;
    // oid_filters, certificate_authorities, psk_key_exchange_modes,
// cookie, supported_versions, early_data, pre_shared_key (RFC 8446)
// all TLS 1.3+ (and possibly DTLS 1.3).
    List<TlsVersion> OID_FILTERS_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> CERTIFICATE_AUTHORITIES_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> PSK_KEY_EXCHANGE_MODES_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> COOKIE_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> SUPPORTED_VERSIONS_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> EARLY_DATA_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> PRE_SHARED_KEY_VERSIONS = KEY_SHARE_VERSIONS;

    // EKT (Encrypted Key Transport for SRTP) is typically DTLS only
// for WebRTC.  If you also support DTLS 1.3, add it; below is an example:
    List<TlsVersion> SUPPORTED_EKT_CIPHERS_VERSIONS = List.of(
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // delegated_credential (RFC 9346 / draft-ietf-tls-subcerts) is for TLS 1.3+.
    List<TlsVersion> DELEGATED_CREDENTIAL_VERSIONS = List.of(
            TlsVersion.TLS13,
            TlsVersion.DTLS13
    );

    // "tls_cert_with_extern_psk", "ticket_pinning", "password_salt", "pwd_clear",
// "pwd_protect" are non-standard/draft.  Often specific to TLS 1.3.
// Adjust if you support them in older versions.
    List<TlsVersion> TLS_CERT_WITH_EXTERN_PSK_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> TICKET_PINNING_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> PASSWORD_SALT_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> PWD_CLEAR_VERSIONS = KEY_SHARE_VERSIONS;
    List<TlsVersion> PWD_PROTECT_VERSIONS = KEY_SHARE_VERSIONS;

    // record_size_limit (RFC 8449) can apply to TLS 1.2+ or DTLS 1.2+
// Also used by some in TLS 1.3.  Shown below for 1.2, 1.3, DTLS 1.2, DTLS 1.3.
    List<TlsVersion> RECORD_SIZE_LIMIT_VERSIONS = List.of(
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // compress_certificate (RFC 8879) is for TLS 1.3+ (and DTLS 1.3).
    List<TlsVersion> COMPRESS_CERTIFICATE_VERSIONS = KEY_SHARE_VERSIONS;

    // padding (RFC 7685) can be used in any TLS/DTLS version that supports extensions.
    List<TlsVersion> PADDING_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // server_certificate_type / client_certificate_type (RFC 7250) typically for <=1.2,
// though some have tried them in 1.3.  Shown for <=1.2 here:
    List<TlsVersion> SERVER_CERTIFICATE_TYPE_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );
    List<TlsVersion> CLIENT_CERTIFICATE_TYPE_VERSIONS = SERVER_CERTIFICATE_TYPE_VERSIONS;

    // signed_certificate_timestamp (SCT) (RFC 6962, updated in RFC 8446) is used
// for TLS 1.2 and TLS 1.3, plus DTLS 1.2/1.3 if implemented.
    List<TlsVersion> SIGNED_CERTIFICATE_TIMESTAMP_VERSIONS = List.of(
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // ALPN (RFC 7301) can be used in all TLS versions (1.0+) and DTLS versions
// that support extensions.  Shown here for all:
    List<TlsVersion> APPLICATION_LAYER_PROTOCOL_NEGOTIATION_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // Heartbeat (RFC 6520) is only valid in TLS 1.0-1.2 and DTLS 1.0-1.2.
    List<TlsVersion> HEARTBEAT_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12
    );

    // use_srtp (RFC 5764) is primarily for DTLS-SRTP, so typically DTLS 1.0/1.2/1.3:
    List<TlsVersion> USE_SRTP_VERSIONS = List.of(
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // signature_algorithms (RFC 5246 & 8446) is used in TLS 1.2 and above.
// Also in DTLS 1.2+, so we include 1.2 & 1.3 in both.
    List<TlsVersion> SIGNATURE_ALGORITHMS_VERSIONS = List.of(
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // supported_groups (RFC 7919, 8446) replaced the older "elliptic_curves" extension.
// It can appear in TLS 1.0-1.3, and DTLS 1.0-1.3.  If you want full coverage:
    List<TlsVersion> SUPPORTED_GROUPS_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // status_request (RFC 6066, 8446) can be used in all TLS versions including 1.3.
    List<TlsVersion> STATUS_REQUEST_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // max_fragment_length (RFC 6066) is typically accepted in all TLS/DTLS versions.
    List<TlsVersion> MAX_FRAGMENT_LENGTH_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // server_name (RFC 6066) is used in all known TLS/DTLS versions.
    List<TlsVersion> SERVER_NAME_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // "connection_id_deprecated" presumably refers to older drafts of DTLS CID
// (RFC 9146).  That extension is DTLS-only: DTLS 1.2 and DTLS 1.3.
    List<TlsVersion> CONNECTION_ID_DEPRECATED_VERSIONS = List.of(
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );

    // "RRC" and "SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS" are unknown or proprietary.
// If you support them in all versions, do so:
    List<TlsVersion> RRC_VERSIONS = List.of(
            TlsVersion.TLS10,
            TlsVersion.TLS11,
            TlsVersion.TLS12,
            TlsVersion.TLS13,
            TlsVersion.DTLS10,
            TlsVersion.DTLS12,
            TlsVersion.DTLS13
    );
    List<TlsVersion> SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS_VERSIONS = RRC_VERSIONS;

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
        return ExtendedMasterSecretExtension.instance();
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
        return SupportedGroupsExtension.recommended();
    }

    static TlsExtension supportedGroups(List<TlsSupportedGroup> groups) {
        return SupportedGroupsExtension.of(groups);
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

    int extensionType();

    List<TlsVersion> versions();

    TlsExtensionDecoder decoder();

    non-sealed interface Concrete extends TlsExtension {
        default void serializeExtension(ByteBuffer buffer) {
            writeLittleEndianInt16(buffer, extensionType());
            writeLittleEndianInt16(buffer, extensionPayloadLength());
            serializeExtensionPayload(buffer);
        }

        default int extensionLength() {
            return INT16_LENGTH + INT16_LENGTH + extensionPayloadLength();
        }

        void serializeExtensionPayload(ByteBuffer buffer);

        int extensionPayloadLength();
    }

    non-sealed interface Configurable extends TlsExtension {
        Optional<? extends Concrete> newInstance(TlsEngine engine);

        Dependencies dependencies();

        sealed interface Dependencies {
            static None none() {
                return None.INSTANCE;
            }

            @SafeVarargs
            static Some some(Class<? extends Concrete>... includedTypes) {
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
                private final Set<Class<? extends Concrete>> includedTypes;

                private Some(Set<Class<? extends Concrete>> includedTypes) {
                    this.includedTypes = includedTypes;
                }

                public Set<Class<? extends Concrete>> includedTypes() {
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
