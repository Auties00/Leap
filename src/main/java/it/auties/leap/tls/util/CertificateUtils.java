package it.auties.leap.tls.util;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.TlsMode;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.util.sun.HostnameChecker;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class CertificateUtils {
    private static final String CLIENT_AUTH_USE_OID = "1.3.6.1.5.5.7.3.2";
    private static final String SERVER_AUTH_USE_OID = "1.3.6.1.5.5.7.3.1";
    private static final String ANY_USE_OID = "2.5.29.37.0";
    private static final int KU_SIGNATURE = 0;
    private static final int KU_KEY_ENCIPHERMENT = 2;
    private static final int KU_KEY_AGREEMENT = 4;
    private static final String DEFAULT_KEY_STORE_PATH = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
    private static final KeyStore DEFAULT_KEY_STORE = loadDefaultKeyStore();

    public static X509Certificate validateChain(List<X509Certificate> certificateChain, InetSocketAddress remoteAddress, KeyStore keyStore, String expectedAlgorithm) {
        var leafCert = getLeafCert(certificateChain);
        checkAlgorithm(expectedAlgorithm, leafCert);
        checkRemote(remoteAddress, leafCert);
        validateCertificate(keyStore, certificateChain);
        return leafCert;
    }

    private static void checkAlgorithm(String expectedAlgorithm, X509Certificate leafCert) {
        var sigAlgName = leafCert.getSigAlgName();
        if (sigAlgName == null || !sigAlgName.toUpperCase().contains(expectedAlgorithm.toUpperCase())) {
            throw new TlsAlert("Certificate signature algorithm (%s) does not match expected algorithm (%s).".formatted(sigAlgName, expectedAlgorithm));
        }
    }

    private static X509Certificate getLeafCert(List<X509Certificate> certificateChain) {
        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new TlsAlert("Remote certificate chain is empty.");
        }

        return certificateChain.getFirst();
    }

    private static void checkRemote(InetSocketAddress remoteAddress, X509Certificate leafCert) {
        try {
            HostnameChecker.match(remoteAddress.getHostName(), leafCert, false);
        } catch (CertificateException e) {
            throw new TlsAlert("Invalid remote address", e);
        }
    }

    private static void validateCertificate(KeyStore trustedKeyStore, List<X509Certificate> certificateChain) {
        var trustAnchors = getTrustAnchors(trustedKeyStore);
        if (trustAnchors.isEmpty()) {
            throw new TlsAlert("Cannot validate certificate: no trust anchors");
        }

        try {
            var certFactory = CertificateFactory.getInstance("X.509");
            var certPath = certFactory.generateCertPath(certificateChain);
            var pkixParams = new PKIXParameters(trustAnchors);
            pkixParams.setRevocationEnabled(false); // Boolean.getBoolean("com.sun.net.ssl.checkRevocation");
            var cpv = CertPathValidator.getInstance("PKIX");
            cpv.validate(certPath, pkixParams);
        }catch (GeneralSecurityException exception) {
            throw new TlsAlert("Cannot validate certificate: certificate error", exception);
        }
    }

    private static Set<TrustAnchor> getTrustAnchors(KeyStore trustStore) {
        try {
            var trustAnchors = new HashSet<TrustAnchor>();
            var aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                var alias = aliases.nextElement();
                if (!trustStore.isCertificateEntry(alias)) {
                    continue;
                }

                var cert = trustStore.getCertificate(alias);
                if (!(cert instanceof X509Certificate x509Certificate)) {
                    continue;
                }

                var anchor = new TrustAnchor(x509Certificate, null);
                trustAnchors.add(anchor);
            }
            return trustAnchors;
        } catch (KeyStoreException exception) {
            throw new TlsAlert("Cannot get trust anchors", exception);
        }
    }

    @SuppressWarnings("NonStrictComparisonCanBeEquality")
    public static void validateUsage(X509Certificate certificate, TlsKeyExchangeType type, TlsMode mode) {
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

    public static KeyStore defaultKeyStore() {
        return DEFAULT_KEY_STORE;
    }

    private static KeyStore loadDefaultKeyStore() {
        var file = new File(CertificateUtils.DEFAULT_KEY_STORE_PATH);
        if (!file.isFile() || !file.canRead()) {
            return null;
        }

        try {
            var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (var fis = new FileInputStream(file)) {
                keyStore.load(fis, null);
                return keyStore;
            } catch (Throwable _) {
                return null;
            }
        }catch (Throwable _) {
            return null;
        }
    }
}
