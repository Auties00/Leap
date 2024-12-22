package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.util.List;

// Extracted from https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv
final class TlsExtensions {
    private TlsExtensions() {

    }

    private static final List<TlsVersion> TLS_UNTIL_12 = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12);
    private static final List<TlsVersion> TLS_UNTIL_13 = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13);
    private static final List<TlsVersion> DTLS_UNTIL_12 = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.DTLS10, TlsVersion.DTLS12);
    private static final List<TlsVersion> DTLS_UNTIL_13 = List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13, TlsVersion.DTLS10, TlsVersion.DTLS12, TlsVersion.DTLS13);

    public static final int SERVER_NAME_TYPE = 0;
    public static final List<TlsVersion> SERVER_NAME_VERSIONS = TLS_UNTIL_13;

    public static final int MAX_FRAGMENT_LENGTH_TYPE = 1;
    public static final List<TlsVersion> MAX_FRAGMENT_LENGTH_VERSIONS = TLS_UNTIL_13;

    public static final int CLIENT_CERTIFICATE_URL_TYPE = 2;
    public static final List<TlsVersion> CLIENT_CERTIFICATE_URL_VERSIONS = TLS_UNTIL_12;

    public static final int TRUSTED_CA_KEYS_TYPE = 3;
    public static final List<TlsVersion> TRUSTED_CA_KEYS_VERSIONS = TLS_UNTIL_12;

    public static final int TRUNCATED_HMAC_TYPE = 4;
    public static final List<TlsVersion> TRUNCATED_HMAC_VERSIONS = TLS_UNTIL_12;

    public static final int STATUS_REQUEST_TYPE = 5;
    public static final List<TlsVersion> STATUS_REQUEST_VERSIONS = TLS_UNTIL_13;

    public static final int USER_MAPPING_TYPE = 6;
    public static final List<TlsVersion> USER_MAPPING_VERSIONS = TLS_UNTIL_12;

    public static final int CLIENT_AUTHZ_TYPE = 7;
    public static final List<TlsVersion> CLIENT_AUTHZ_VERSIONS = TLS_UNTIL_12;

    public static final int SERVER_AUTHZ_TYPE = 8;
    public static final List<TlsVersion> SERVER_AUTHZ_VERSIONS = TLS_UNTIL_12;

    public static final int CERT_TYPE_TYPE = 9;
    public static final List<TlsVersion> CERT_TYPE_VERSIONS = TLS_UNTIL_12;

    public static final int SUPPORTED_GROUPS_TYPE = 10;
    public static final List<TlsVersion> SUPPORTED_GROUPS_VERSIONS = TLS_UNTIL_13;

    public static final int EC_POINT_FORMATS_TYPE = 11;
    public static final List<TlsVersion> EC_POINT_FORMATS_VERSIONS = TLS_UNTIL_12;

    public static final int SRP_TYPE = 12;
    public static final List<TlsVersion> SRP_VERSIONS = TLS_UNTIL_12;

    public static final int SIGNATURE_ALGORITHMS_TYPE = 13;
    public static final List<TlsVersion> SIGNATURE_ALGORITHMS_VERSIONS = TLS_UNTIL_13;

    public static final int USE_SRTP_TYPE = 14;
    public static final List<TlsVersion> USE_SRTP_VERSIONS = TLS_UNTIL_13;

    public static final int HEARTBEAT_TYPE = 15;
    public static final List<TlsVersion> HEARTBEAT_VERSIONS = TLS_UNTIL_13;

    public static final int APPLICATION_LAYER_PROTOCOL_NEGOTIATION_TYPE = 16;
    public static final List<TlsVersion> APPLICATION_LAYER_PROTOCOL_NEGOTIATION_VERSIONS = TLS_UNTIL_13;

    public static final int STATUS_REQUEST_V2_TYPE = 17;
    public static final List<TlsVersion> STATUS_REQUEST_V2_VERSIONS = TLS_UNTIL_12;

    public static final int SIGNED_CERTIFICATE_TIMESTAMP_TYPE = 18;
    public static final List<TlsVersion> SIGNED_CERTIFICATE_TIMESTAMP_VERSIONS = TLS_UNTIL_13;

    public static final int CLIENT_CERTIFICATE_TYPE_TYPE = 19;
    public static final List<TlsVersion> CLIENT_CERTIFICATE_TYPE_VERSIONS = TLS_UNTIL_13;

    public static final int SERVER_CERTIFICATE_TYPE_TYPE = 20;
    public static final List<TlsVersion> SERVER_CERTIFICATE_TYPE_VERSIONS = TLS_UNTIL_13;

    public static final int PADDING_TYPE = 21;
    public static final List<TlsVersion> PADDING_VERSIONS = TLS_UNTIL_13;

    public static final int ENCRYPT_THEN_MAC_TYPE = 22;
    public static final List<TlsVersion> ENCRYPT_THEN_MAC_VERSIONS = TLS_UNTIL_12;

    public static final int EXTENDED_MASTER_SECRET_TYPE = 23;
    public static final List<TlsVersion> EXTENDED_MASTER_SECRET_VERSIONS = TLS_UNTIL_12;

    public static final int TOKEN_BINDING_TYPE = 24;
    public static final List<TlsVersion> TOKEN_BINDING_VERSIONS = TLS_UNTIL_12;

    public static final int CACHED_INFO_TYPE = 25;
    public static final List<TlsVersion> CACHED_INFO_VERSIONS = TLS_UNTIL_12;

    public static final int TLS_LTS_TYPE = 26;
    public static final List<TlsVersion> TLS_LTS_VERSIONS = TLS_UNTIL_12;

    public static final int COMPRESS_CERTIFICATE_TYPE = 27;
    public static final List<TlsVersion> COMPRESS_CERTIFICATE_VERSIONS = TLS_UNTIL_13;

    public static final int RECORD_SIZE_LIMIT_TYPE = 28;
    public static final List<TlsVersion> RECORD_SIZE_LIMIT_VERSIONS = TLS_UNTIL_13;

    public static final int PWD_PROTECT_TYPE = 29;
    public static final List<TlsVersion> PWD_PROTECT_VERSIONS = TLS_UNTIL_13;

    public static final int PWD_CLEAR_TYPE = 30;
    public static final List<TlsVersion> PWD_CLEAR_VERSIONS = TLS_UNTIL_13;

    public static final int PASSWORD_SALT_TYPE = 31;
    public static final List<TlsVersion> PASSWORD_SALT_VERSIONS = TLS_UNTIL_13;

    public static final int TICKET_PINNING_TYPE = 32;
    public static final List<TlsVersion> TICKET_PINNING_VERSIONS = TLS_UNTIL_13;

    public static final int TLS_CERT_WITH_EXTERN_PSK_TYPE = 33;
    public static final List<TlsVersion> TLS_CERT_WITH_EXTERN_PSK_VERSIONS = TLS_UNTIL_13;

    public static final int DELEGATED_CREDENTIAL_TYPE = 34;
    public static final List<TlsVersion> DELEGATED_CREDENTIAL_VERSIONS = TLS_UNTIL_13;

    public static final int SESSION_TICKET_TYPE = 35;
    public static final List<TlsVersion> SESSION_TICKET_VERSIONS = TLS_UNTIL_12;

    public static final int TLMSP_TYPE = 36;
    public static final List<TlsVersion> TLMSP_VERSIONS = TLS_UNTIL_12;

    public static final int TLMSP_PROXYING_TYPE = 37;
    public static final List<TlsVersion> TLMSP_PROXYING_VERSIONS = TLS_UNTIL_12;

    public static final int TLMSP_DELEGATE_TYPE = 38;
    public static final List<TlsVersion> TLMSP_DELEGATE_VERSIONS = TLS_UNTIL_12;

    public static final int SUPPORTED_EKT_CIPHERS_TYPE = 39;
    public static final List<TlsVersion> SUPPORTED_EKT_CIPHERS_VERSIONS = TLS_UNTIL_13;

    public static final int PRE_SHARED_KEY_TYPE = 41;
    public static final List<TlsVersion> PRE_SHARED_KEY_VERSIONS = TLS_UNTIL_13;

    public static final int EARLY_DATA_TYPE = 42;
    public static final List<TlsVersion> EARLY_DATA_VERSIONS = TLS_UNTIL_13;

    public static final int SUPPORTED_VERSIONS_TYPE = 43;
    public static final List<TlsVersion> SUPPORTED_VERSIONS_VERSIONS = TLS_UNTIL_13;

    public static final int COOKIE_TYPE = 44;
    public static final List<TlsVersion> COOKIE_VERSIONS = TLS_UNTIL_13;

    public static final int PSK_KEY_EXCHANGE_MODES_TYPE = 45;
    public static final List<TlsVersion> PSK_KEY_EXCHANGE_MODES_VERSIONS = TLS_UNTIL_13;

    public static final int CERTIFICATE_AUTHORITIES_TYPE = 47;
    public static final List<TlsVersion> CERTIFICATE_AUTHORITIES_VERSIONS = TLS_UNTIL_13;

    public static final int OID_FILTERS_TYPE = 48;
    public static final List<TlsVersion> OID_FILTERS_VERSIONS = TLS_UNTIL_13;

    public static final int POST_HANDSHAKE_AUTH_TYPE = 49;
    public static final List<TlsVersion> POST_HANDSHAKE_AUTH_VERSIONS = TLS_UNTIL_13;

    public static final int SIGNATURE_ALGORITHMS_CERT_TYPE = 50;
    public static final List<TlsVersion> SIGNATURE_ALGORITHMS_CERT_VERSIONS = TLS_UNTIL_13;

    public static final int KEY_SHARE_TYPE = 51;
    public static final List<TlsVersion> KEY_SHARE_VERSIONS = TLS_UNTIL_13;

    public static final int TRANSPARENCY_INFO_TYPE = 52;
    public static final List<TlsVersion> TRANSPARENCY_INFO_VERSIONS = TLS_UNTIL_13;

    public static final int CONNECTION_ID_DEPRECATED_TYPE = 53;
    public static final List<TlsVersion> CONNECTION_ID_DEPRECATED_VERSIONS = DTLS_UNTIL_12;

    public static final int CONNECTION_ID_TYPE = 54;
    public static final List<TlsVersion> CONNECTION_ID_VERSIONS = DTLS_UNTIL_13;

    public static final int EXTERNAL_ID_HASH_TYPE = 55;
    public static final List<TlsVersion> EXTERNAL_ID_HASH_VERSIONS = TLS_UNTIL_13;

    public static final int EXTERNAL_SESSION_ID_TYPE = 56;
    public static final List<TlsVersion> EXTERNAL_SESSION_ID_VERSIONS = TLS_UNTIL_13;

    public static final int QUIC_TRANSPORT_PARAMETERS_TYPE = 57;
    public static final List<TlsVersion> QUIC_TRANSPORT_PARAMETERS_VERSIONS = TLS_UNTIL_13;

    public static final int TICKET_REQUEST_TYPE = 58;
    public static final List<TlsVersion> TICKET_REQUEST_VERSIONS = TLS_UNTIL_13;

    public static final int DNSSEC_CHAIN_TYPE = 59;
    public static final List<TlsVersion> DNSSEC_CHAIN_VERSIONS = TLS_UNTIL_13;

    public static final int SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS_TYPE = 60;
    public static final List<TlsVersion> SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS_VERSIONS = DTLS_UNTIL_13;

    public static final int RRC_TYPE = 61;
    public static final List<TlsVersion> RRC_VERSIONS = DTLS_UNTIL_13;

    public static final int TLS_FLAGS_TYPE = 62;
    public static final List<TlsVersion> TLS_FLAGS_VERSIONS = TLS_UNTIL_13;

    public static final int NEXT_PROTOCOL_NEGOTIATION_TYPE = 0x3374;
    public static final List<TlsVersion> NEXT_PROTOCOL_NEGOTIATION_VERSIONS = TLS_UNTIL_13;

    public static final int ECH_OUTER_EXTENSIONS_TYPE = 64768;
    public static final List<TlsVersion> ECH_OUTER_EXTENSIONS_VERSIONS = TLS_UNTIL_13;

    public static final int ENCRYPTED_CLIENT_HELLO_TYPE = 65037;
    public static final List<TlsVersion> ENCRYPTED_CLIENT_HELLO_VERSIONS = TLS_UNTIL_13;

    public static final int RENEGOTIATION_INFO_TYPE = 65281;
    public static final List<TlsVersion> RENEGOTIATION_INFO_VERSIONS = TLS_UNTIL_12;

    public static final List<TlsVersion> GREASE_VERSIONS = List.of(TlsVersion.TLS12, TlsVersion.TLS13);
}
