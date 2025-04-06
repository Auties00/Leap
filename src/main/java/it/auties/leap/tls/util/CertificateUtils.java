package it.auties.leap.tls.util;

import it.auties.leap.StableValue;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.util.sun.HostnameChecker;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public final class CertificateUtils {
    private static final String CLIENT_AUTH_USE_OID = "1.3.6.1.5.5.7.3.2";
    private static final String SERVER_AUTH_USE_OID = "1.3.6.1.5.5.7.3.1";
    private static final String ANY_USE_OID = "2.5.29.37.0";
    private static final int KU_SIGNATURE = 0;
    private static final int KU_KEY_ENCIPHERMENT = 2;
    private static final int KU_KEY_AGREEMENT = 4;
    private static final String DEFAULT_KEY_STORE_PATH = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
    private static final StableValue<List<TlsCertificate>> DEFAULT_TRUST_ANCHORS = StableValue.of();

    public static TlsCertificate validateChain(InetSocketAddress remoteAddress, List<TlsCertificate> certificates, List<TlsCertificate> trustAnchors, String expectedAlgorithm) {
        var leafCert = getLeafCert(certificates);
        checkAlgorithm(expectedAlgorithm, leafCert);
        checkRemote(remoteAddress, leafCert);
        validateCertificate(trustAnchors, certificates);
        return leafCert;
    }

    private static void checkAlgorithm(String expectedAlgorithm, TlsCertificate leafCert) {
        var sigAlgName = leafCert.value().getSigAlgName();
        if (sigAlgName == null || !sigAlgName.toUpperCase().contains(expectedAlgorithm.toUpperCase())) {
            throw new TlsAlert("Certificate signature algorithm (%s) does not match expected algorithm (%s).".formatted(sigAlgName, expectedAlgorithm));
        }
    }

    private static TlsCertificate getLeafCert(List<TlsCertificate> certificateChain) {
        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new TlsAlert("Remote certificate chain is empty.");
        }

        return certificateChain.getFirst();
    }

    private static void checkRemote(InetSocketAddress remoteAddress, TlsCertificate leafCert) {
        try {
            HostnameChecker.match(remoteAddress.getHostName(), leafCert.value(), false);
        } catch (CertificateException e) {
            throw new TlsAlert("Invalid remote address", e);
        }
    }

    private static void validateCertificate(List<TlsCertificate> trusted, List<TlsCertificate> certificateChain) {
        try {
            var certFactory = CertificateFactory.getInstance("X.509");
            var path = new ArrayList<X509Certificate>();
            var trustAnchors = new HashSet<TrustAnchor>();
            for(var trustAnchor : trusted) {
                path.add(trustAnchor.value());
                trustAnchors.add(new TrustAnchor(trustAnchor.value(), null));
            }
            var certPath = certFactory.generateCertPath(path);
            var pkixParams = new PKIXParameters(trustAnchors);
            pkixParams.setRevocationEnabled(false); // Boolean.getBoolean("com.sun.net.ssl.checkRevocation");
            var cpv = CertPathValidator.getInstance("PKIX");
            cpv.validate(certPath, pkixParams);
        }catch (GeneralSecurityException exception) {
            throw new TlsAlert("Cannot validate certificate: certificate error", exception);
        }
    }

    @SuppressWarnings("NonStrictComparisonCanBeEquality")
    public static void validateUsage(X509Certificate certificate, TlsKeyExchangeType type, TlsConnectionType mode) {
        var keyUsage = certificate.getKeyUsage();
        var extendedKeyUsage = getExtendedKeyUsageIfParsable(certificate);
        switch (mode) {
            case CLIENT -> {
                if(keyUsage != null) {
                    switch (type) {
                        case STATIC -> {
                            if (keyUsage.length <= KU_KEY_ENCIPHERMENT || !keyUsage[KU_KEY_ENCIPHERMENT]) {
                                throw new TlsAlert("Extended key usage does not permit key encipherment");
                            }

                            if (keyUsage.length <= KU_KEY_AGREEMENT || !keyUsage[KU_KEY_AGREEMENT]) {
                                throw new TlsAlert("Extended key usage does not permit key agreement");
                            }
                        }
                        case EPHEMERAL -> {
                            if (keyUsage.length <= KU_SIGNATURE || !keyUsage[KU_SIGNATURE]) {
                                throw new TlsAlert("Extended key usage does not permit digital signature");
                            }
                        }
                    }
                }

                if(extendedKeyUsage != null
                        && !extendedKeyUsage.contains(ANY_USE_OID)
                        && !extendedKeyUsage.contains(SERVER_AUTH_USE_OID)) {
                    throw new TlsAlert("Extended key usage does not permit use for TLS server authentication");
                }
            }

            case SERVER -> {
                if (keyUsage != null && (keyUsage.length <= KU_SIGNATURE || !keyUsage[KU_SIGNATURE])) {
                    throw new TlsAlert("Extended key usage does not permit digital signature");
                }

                if (extendedKeyUsage != null
                        && !extendedKeyUsage.contains(ANY_USE_OID)
                        && !extendedKeyUsage.contains(CLIENT_AUTH_USE_OID)) {
                    throw new TlsAlert("Extended key usage does not permit use for TLS client authentication");
                }
            }
        }
    }

    private static List<String> getExtendedKeyUsageIfParsable(X509Certificate certificate) {
        try {
            return certificate.getExtendedKeyUsage();
        }catch (CertificateParsingException exception) {
            return null;
        }
    }

    public static List<TlsCertificate> defaultTrustAnchors() {
        return DEFAULT_TRUST_ANCHORS.orElseSet(() -> {
            var file = new File(CertificateUtils.DEFAULT_KEY_STORE_PATH);
            if (!file.isFile() || !file.canRead()) {
                throw new TlsAlert("Cannot load default trust anchors: " + file + " is not a file or cannot be read");
            }

            try {
                var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                try (var fis = new FileInputStream(file)) {
                    keyStore.load(fis, null);
                    var trustAnchors = new ArrayList<TlsCertificate>();
                    var aliases = keyStore.aliases();
                    while (aliases.hasMoreElements()) {
                        var alias = aliases.nextElement();
                        if (!keyStore.isCertificateEntry(alias)) {
                            continue;
                        }

                        var cert = keyStore.getCertificate(alias);
                        if (!(cert instanceof X509Certificate x509Certificate)) {
                            continue;
                        }

                        trustAnchors.add(TlsCertificate.of(x509Certificate));
                    }
                    return trustAnchors;
                }
            } catch (Throwable throwable) {
                throw new TlsAlert("Cannot load default trust anchors", throwable);
            }
        });
    }
}
