package it.auties.leap.tls.certificate;

import it.auties.leap.tls.util.CertificateUtils;

import java.util.*;

public final class TlsCertificateStoreBuilder {

    private final Set<TlsClientCertificateType> supportedTypes;
    private final Map<TlsClientCertificateType, TlsCertificate> certificates;
    private final Set<TlsCertificate> trustAnchors;
    private TlsCertificateChainValidator validator;

    TlsCertificateStoreBuilder(Set<TlsClientCertificateType> supportedTypes) {
        this.supportedTypes = supportedTypes;
        this.certificates = new HashMap<>();
        this.trustAnchors = new HashSet<>();
    }

    public TlsCertificateStoreBuilder certificate(TlsCertificate certificate) {
        if(!supportedTypes.contains(certificate.type())) {
            throw new IllegalArgumentException("Certificate type " + certificate.type() + " is not supported");
        }

        if(certificates.containsKey(certificate.type())) {
            throw new IllegalArgumentException("Certificate type " + certificate.type() + " is already added");
        }

        certificates.put(certificate.type(), certificate);
        return this;
    }

    public TlsCertificateStoreBuilder certificates(Collection<? extends TlsCertificate> certificates) {
        if(certificates != null) {
            for(var certificate : certificates) {
                certificate(certificate);
            }
        }

        return this;
    }

    public TlsCertificateStoreBuilder trustAnchors(TlsCertificate trustAnchor) {
        this.trustAnchors.add(trustAnchor);
        return this;
    }


    public TlsCertificateStoreBuilder trustAnchors(Set<TlsCertificate> trustAnchors) {
        if(trustAnchors != null) {
            this.trustAnchors.addAll(trustAnchors);
        }
        return this;
    }

    public TlsCertificateStoreBuilder validator(TlsCertificateChainValidator validator) {
        this.validator = validator;
        return this;
    }

    public TlsCertificateStore build() {
        var trustAnchors = Objects.requireNonNullElseGet(this.trustAnchors, CertificateUtils::defaultTrustAnchors);
        var validator = Objects.requireNonNullElse(this.validator, TlsCertificateChainValidator.validate());
        return new TlsCertificateStore(certificates, trustAnchors, validator);
    }
}
