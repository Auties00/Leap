package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.util.CertificateUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.util.List;

public final class ValidateCertificatesValidator implements TlsCertificateValidator {
    private final List<TlsCertificate> trustAnchors;

    public ValidateCertificatesValidator(List<TlsCertificate> trustAnchors) {
        this.trustAnchors = trustAnchors;
    }

    @Override
    public TlsCertificate validate(TlsContext context, TlsSource source, List<TlsCertificate> certificates) {
        var version = context.getNegotiatedValue(TlsContextualProperty.version())
                .orElse(null);
        if(version == null) {
            throw new TlsAlert(
                    "Cannot validate certificates: no version was negotiated",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.HANDSHAKE_FAILURE
            );
        }

        var cipher = context.getNegotiatedValue(TlsContextualProperty.cipher())
                .orElse(null);
        if(cipher == null) {
            throw new TlsAlert(
                    "Cannot validate certificates: no cipher was negotiated",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.HANDSHAKE_FAILURE
            );
        }

        if(version == TlsVersion.TLS13 || version == TlsVersion.DTLS13) {
            return CertificateUtils.validateChain(
                    context.address().orElse(null),
                    certificates,
                    trustAnchors,
                    null
            );
        }

        return cipher.auth()
                .orElseThrow(() -> new TlsAlert(
                        "Cannot validate certificates: no authentication is provided by the negotiated cipher",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.HANDSHAKE_FAILURE
                ))
                .validate(context, certificates, trustAnchors);
    }
}
