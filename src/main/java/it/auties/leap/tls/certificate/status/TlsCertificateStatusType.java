package it.auties.leap.tls.certificate.status;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

//   https://datatracker.ietf.org/doc/rfc6961/
//   Section 2.1 defines the new TLS extension status_request_v2 (17)
//   enum, which has been added to the "ExtensionType Values" list in the
//   IANA "Transport Layer Security (TLS) Extensions" registry.
//
//   Section 2.2 describes a TLS CertificateStatusType registry that is
//   now maintained by IANA.  The "TLS Certificate Status Types" registry
//   has been created under the "Transport Layer Security (TLS)
//   Extensions" registry.  CertificateStatusType values are to be
//   assigned via IETF Review as defined in [RFC5226].  The initial
//   registry corresponds to the definition of "CertificateStatusType" in
//   Section 2.2.
//
//   Value   Description   Reference
//   -----------------------------------------
//   0       Reserved      [RFC6961]
//   1       ocsp          [RFC6066] [RFC6961]
//   2       ocsp_multi    [RFC6961]
//   3-255   Unassigned
public enum TlsCertificateStatusType implements TlsIdentifiableProperty<Byte> {
    OCSP((byte) 1),
    OCSP_MULTI((byte) 2);

    private static final Map<Byte, TlsCertificateStatusType> VALUES = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(TlsCertificateStatusType::id, Function.identity()));

    private final byte id;
  
    TlsCertificateStatusType(byte id) {
        this.id = id;
    }

    public static Optional<TlsCertificateStatusType> of(byte id) {
        return Optional.ofNullable(VALUES.get(id));
    }

    @Override
    public Byte id() {
        return id;
    }
}
