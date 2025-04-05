package it.auties.leap.tls.certificate;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class TlsCertificateStore {
    private final Map<TlsClientCertificateType, TlsCertificate> certificates;
    private final Set<TlsCertificate> trustAnchors;
    private final TlsCertificateChainValidator validator;

    TlsCertificateStore(Map<TlsClientCertificateType, TlsCertificate> certificates, Set<TlsCertificate> trustAnchors, TlsCertificateChainValidator validator) {
        this.trustAnchors = trustAnchors;
        this.validator = validator;
        this.certificates = certificates;
    }

    public static TlsCertificateStoreBuilder newBuilder(Set<TlsClientCertificateType> supportedTypes) {
        return new TlsCertificateStoreBuilder(supportedTypes);
    }

    public Optional<TlsCertificate> getCertificate(TlsClientCertificateType type) {
        return Optional.ofNullable(certificates.get(type));
    }

    public Set<TlsCertificate> trustAnchors() {
        return trustAnchors;
    }

    public TlsCertificateChainValidator validator() {
        return validator;
    }
}
