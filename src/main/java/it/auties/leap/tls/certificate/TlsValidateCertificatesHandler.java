package it.auties.leap.tls.certificate;

import it.auties.leap.tls.TlsCertificatesHandler;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

public final class TlsValidateCertificatesHandler implements TlsCertificatesHandler {
    public static final TlsValidateCertificatesHandler INSTANCE = new TlsValidateCertificatesHandler();

    // sun.security.util.KnownOIDs
    private static final String CLIENT_AUTH_USE_OID = "1.3.6.1.5.5.7.3.2";
    private static final String ANY_USE_OID = "2.5.29.37.0";

    private final TrustManagerFactory factory;
    private TlsValidateCertificatesHandler() {
        try {
            this.factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot initialize trust manager", exception);
        }
    }

    @Override
    public void accept(InetSocketAddress remoteAddress, List<X509Certificate> certificates, Source certificatesSource) {
        try {
            Objects.requireNonNull(certificates, "Missing certificates");
            var validCertificates = getClientCertificates(certificates);
            if(validCertificates.length == 0) {
                throw new RuntimeException("Cannot validate X509 certificates: no certificates found");
            }

            var authType = getKeyAlgorithm(validCertificates);
            var validated = validate(validCertificates, authType);
            if(!validated) {
                throw new RuntimeException("No X509 certificate validator found");
            }
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot validate X509 certificates", exception);
        }
    }

    private X509Certificate[] getClientCertificates(List<X509Certificate> certificates) {
        return certificates.stream()
                .filter(this::hasClientAuth)
                .toArray(X509Certificate[]::new);
    }

    private boolean validate(X509Certificate[] validCertificates, String authType) throws CertificateException {
        var validated = false;
        for(var trustManager : factory.getTrustManagers()) {
            if((trustManager instanceof X509TrustManager x509TrustManager)) {
                x509TrustManager.checkClientTrusted(validCertificates, authType);
                validated = true;
            }
        }
        return validated;
    }

    private String getKeyAlgorithm(X509Certificate[] validCertificates) {
        var keyAlgorithm = validCertificates[0].getPublicKey().getAlgorithm();
        return switch (keyAlgorithm) {
            case "RSA", "DSA", "EC", "RSASSA-PSS" -> keyAlgorithm;
            default -> "UNKNOWN";
        };
    }

    // sun.security.validator.EndEntityChecker
    private boolean hasClientAuth(X509Certificate entry) {
        try {
            var extendedKeyUsage = entry.getExtendedKeyUsage();
            return extendedKeyUsage == null
                    || extendedKeyUsage.contains(ANY_USE_OID)
                    || extendedKeyUsage.contains(CLIENT_AUTH_USE_OID);
        }catch (CertificateException exception) {
            return false;
        }
    }
}
