package it.auties.leap.tls.util;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.exception.TlsException;
import sun.security.util.HostnameChecker;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public final class CertificateUtils {
    private static final String CLIENT_AUTH_USE_OID = "1.3.6.1.5.5.7.3.2";
    private static final String SERVER_AUTH_USE_OID = "1.3.6.1.5.5.7.3.1";
    private static final String ANY_USE_OID = "2.5.29.37.0";
    private static final int KU_SIGNATURE = 0;
    private static final int KU_KEY_ENCIPHERMENT = 2;
    private static final int KU_KEY_AGREEMENT = 4;
    private static final String DEFAULT_STORE_PATH = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security";
    private static final String DEFAULT_STORE = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
    private static final String JSSE_DEFAULT_STORE = DEFAULT_STORE_PATH + File.separator + "jssecacerts";

    public static X509Certificate validateChain(
            TlsContext context,
            TlsSource source,
            String expectedAlgorithm
    ) {
        var certificateChain = switch (source) {
            case REMOTE -> context.remoteCertificates();
            case LOCAL -> context.localCertificates();
        };
        var remoteAddress = context.remoteAddress()
                .orElseThrow(() -> new TlsException("Cannot validate certificate chain: remote address wasn't set"));
        var leafCert = getLeafCert(certificateChain);
        checkAlgorithm(expectedAlgorithm, leafCert);
        checkRemote(remoteAddress, leafCert);
        validateCertificate(context.config().trustedKeyStore(), certificateChain);
        return leafCert;
    }

    private static void checkAlgorithm(String expectedAlgorithm, X509Certificate leafCert) {
        var sigAlgName = leafCert.getSigAlgName();
        if (sigAlgName == null || !sigAlgName.toUpperCase().contains(expectedAlgorithm.toUpperCase())) {
            throw new TlsException("Certificate signature algorithm (%s) does not match expected algorithm (%s).".formatted(sigAlgName, expectedAlgorithm));
        }
    }

    private static X509Certificate getLeafCert(List<X509Certificate> certificateChain) {
        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new TlsException("Remote certificate chain is empty.");
        }

        return certificateChain.getFirst();
    }

    private static void checkRemote(InetSocketAddress remoteAddress, X509Certificate leafCert) {
        try {
            HostnameChecker.getInstance(HostnameChecker.TYPE_TLS)
                    .match(remoteAddress.getHostName(), leafCert);
        } catch (CertificateException e) {
            throw new TlsException("Invalid remote address", e);
        }
    }

    private static void validateCertificate(KeyStore trustedKeyStore, List<X509Certificate> certificateChain) {
        var trustAnchors = getTrustAnchors(trustedKeyStore);
        if (trustAnchors.isEmpty()) {
            throw new TlsException("Cannot validate certificate: no trust anchors");
        }

        try {
            var certFactory = CertificateFactory.getInstance("X.509");
            var certPath = certFactory.generateCertPath(certificateChain);
            var pkixParams = new PKIXParameters(trustAnchors);
            pkixParams.setRevocationEnabled(false); // Boolean.getBoolean("com.sun.net.ssl.checkRevocation");
            var cpv = CertPathValidator.getInstance("PKIX");
            cpv.validate(certPath, pkixParams);
        }catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot validate certificate: certificate error", exception);
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
            throw new TlsException("Cannot get trust anchors", exception);
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
                                throw new TlsException("Extended key usage does not permit key encipherment");
                            }

                            if (keyUsage.length <= KU_KEY_AGREEMENT || !keyUsage[KU_KEY_AGREEMENT]) {
                                throw new TlsException("Extended key usage does not permit key agreement");
                            }
                        }
                        case EPHEMERAL -> {
                            if (keyUsage.length <= KU_SIGNATURE || !keyUsage[KU_SIGNATURE]) {
                                throw new TlsException("Extended key usage does not permit digital signature");
                            }
                        }
                    }
                }

                if(extendedKeyUsage != null
                        && !extendedKeyUsage.contains(ANY_USE_OID)
                        && !extendedKeyUsage.contains(SERVER_AUTH_USE_OID)) {
                    throw new TlsException("Extended key usage does not permit use for TLS server authentication");
                }
            }

            case SERVER -> {
                if (keyUsage != null && (keyUsage.length <= KU_SIGNATURE || !keyUsage[KU_SIGNATURE])) {
                    throw new TlsException("Extended key usage does not permit digital signature");
                }

                if (extendedKeyUsage != null
                        && !extendedKeyUsage.contains(ANY_USE_OID)
                        && !extendedKeyUsage.contains(CLIENT_AUTH_USE_OID)) {
                    throw new TlsException("Extended key usage does not permit use for TLS client authentication");
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

    public static KeyStore getDefaultKeyStore() {
        var storePropName = System.getProperty("javax.net.ssl.trustStore");
        var storePropType = System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType());
        var storePropProvider = System.getProperty("javax.net.ssl.trustStoreProvider");
        var storePropPassword = System.getProperty("javax.net.ssl.trustStorePassword");
        if(storePropName != null && !storePropName.equals("NONE")) {
            var keyStore = getKeyStore(storePropName, storePropProvider, storePropType, storePropPassword);
            if(keyStore.isPresent()) {
                return keyStore.get();
            }
        }
        return getKeyStore(DEFAULT_STORE, storePropProvider, storePropType, storePropPassword)
                .orElseThrow(() -> new TlsException(""));
    }

    private static Optional<KeyStore> getKeyStore(String fileName, String storePropProvider, String storePropType, String storePropPassword) {
        var file = new File(fileName);
        if (!file.isFile() || !file.canRead()) {
            return Optional.empty();
        }

        return getKeyStore(storePropProvider, storePropType).flatMap(keyStore -> {
            var password = storePropPassword == null ? null : storePropPassword.toCharArray();
            try (var fis = new FileInputStream(file)) {
                keyStore.load(fis, password);
                return Optional.of(keyStore);
            } catch (Throwable _) {
                return Optional.empty();
            }
        });
    }

    private static Optional<KeyStore> getKeyStore(String storePropProvider, String storePropType) {
        try {
            if (storePropProvider == null) {
                return Optional.of(KeyStore.getInstance(storePropType));
            }

            return Optional.of(KeyStore.getInstance(storePropType, storePropProvider));
        }catch (GeneralSecurityException exception) {
            return Optional.empty();
        }
    }
}
