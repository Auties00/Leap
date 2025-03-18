package it.auties.leap.tls.util;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.exception.TlsException;

import javax.net.ssl.SNIHostName;
import java.io.File;
import java.io.FileInputStream;
import java.net.IDN;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.text.Normalizer;
import java.util.*;

public final class CertificateUtils {
    private static final String CLIENT_AUTH_USE_OID = "1.3.6.1.5.5.7.3.2";
    private static final String SERVER_AUTH_USE_OID = "1.3.6.1.5.5.7.3.1";
    private static final String ANY_USE_OID = "2.5.29.37.0";
    private static final int KU_SIGNATURE = 0;
    private static final int KU_KEY_ENCIPHERMENT = 2;
    private static final int KU_KEY_AGREEMENT = 4;
    private static final String DEFAULT_STORE = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";

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
            match(remoteAddress.getHostName(), leafCert, false);
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

    private static final int ALTNAME_DNS = 2;
    private static final int ALTNAME_IP  = 7;

    public static void match(String expectedName, X509Certificate cert,
                             boolean chainsToPublicCA) throws CertificateException {
        if (expectedName == null) {
            throw new CertificateException("Hostname or IP address is " + "undefined.");
        }

        if (IPAddressUtil.isIPv4LiteralAddress(expectedName) || IPAddressUtil.isIPv6LiteralAddress(expectedName)) {
            matchIP(expectedName, cert);
        } else {
            matchDNS(expectedName, cert, chainsToPublicCA);
        }
    }

    private static void matchIP(String expectedIP, X509Certificate cert)
            throws CertificateException {
        Collection<List<?>> subjAltNames = cert.getSubjectAlternativeNames();
        if (subjAltNames == null) {
            throw new CertificateException
                    ("No subject alternative names present");
        }
        for (List<?> next : subjAltNames) {
            // For IP address, it needs to be exact match
            if (((Integer)next.get(0)).intValue() == ALTNAME_IP) {
                String ipAddress = (String)next.get(1);
                if (expectedIP.equalsIgnoreCase(ipAddress)) {
                    return;
                } else {
                    // compare InetAddress objects in order to ensure
                    // equality between a long IPv6 address and its
                    // abbreviated form.
                    try {
                        if (InetAddress.getByName(expectedIP).equals(
                                InetAddress.getByName(ipAddress))) {
                            return;
                        }
                    } catch (UnknownHostException e) {}
                }
            }
        }
        throw new CertificateException("No subject alternative " +
                "names matching " + "IP address " +
                expectedIP + " found");
    }

    private static void matchDNS(String expectedName, X509Certificate cert,
                                 boolean chainsToPublicCA)
            throws CertificateException {
        // Check that the expected name is a valid domain name.
        try {
            // Using the checking implemented in SNIHostName
            SNIHostName sni = new SNIHostName(expectedName);
        } catch (IllegalArgumentException iae) {
            throw new CertificateException(
                    "Illegal given domain name: " + expectedName, iae);
        }

        Collection<List<?>> subjAltNames = cert.getSubjectAlternativeNames();
        if (subjAltNames != null) {
            boolean foundDNS = false;
            for (List<?> next : subjAltNames) {
                if (((Integer)next.get(0)).intValue() == ALTNAME_DNS) {
                    foundDNS = true;
                    String dnsName = (String)next.get(1);
                    if (isMatched(expectedName, dnsName, chainsToPublicCA)) {
                        return;
                    }
                }
            }
            if (foundDNS) {
                // if certificate contains any subject alt names of type DNS
                // but none match, reject
                throw new CertificateException("No subject alternative DNS "
                        + "name matching " + expectedName + " found.");
            }
        }
        var cname = cert.getSubjectX500Principal().getName();
        if (cname != null) {
            if (!Normalizer.isNormalized(cname, Normalizer.Form.NFKC)) {
                throw new CertificateException("Not a formal name " + cname);
            }
            if (isMatched(expectedName, cname, chainsToPublicCA)) {
                return;
            }
        }
        String msg = "No name matching " + expectedName + " found";
        throw new CertificateException(msg);
    }

    private static boolean isMatched(String name, String template,
                                     boolean chainsToPublicCA) {

        // Normalize to Unicode, because PSL is in Unicode.
        try {
            name = IDN.toUnicode(IDN.toASCII(name));
            template = IDN.toUnicode(IDN.toASCII(template));
        } catch (RuntimeException re) {
            return false;
        }

        if (hasIllegalWildcard(template, chainsToPublicCA)) {
            return false;
        }

        // check the validity of the domain name template.
        try {
            // Replacing wildcard character '*' with 'z' to check
            // the domain name template validity.
            //
            // Using the checking implemented in SNIHostName
            new SNIHostName(template.replace('*', 'z'));
        } catch (IllegalArgumentException iae) {
            // It would be nice to add debug log if not matching.
            return false;
        }

        return matchLeftmostWildcard(name, template);
    }

    /**
     * Returns true if the template contains an illegal wildcard character.
     */
    private static boolean hasIllegalWildcard(
            String template, boolean chainsToPublicCA) {
        // not ok if it is a single wildcard character or "*."
        if (template.equals("*") || template.equals("*.")) {
            return true;
        }

        int lastWildcardIndex = template.lastIndexOf("*");

        // ok if it has no wildcard character
        if (lastWildcardIndex == -1) {
            return false;
        }

        String afterWildcard = template.substring(lastWildcardIndex);
        int firstDotIndex = afterWildcard.indexOf(".");

        // not ok if there is no dot after wildcard (ex: "*com")
        if (firstDotIndex == -1) {
            return true;
        }

        if (!chainsToPublicCA) {
            return false; // skip check for non-public certificates
        }

        // If the wildcarded domain is a top-level domain under which names
        // can be registered, then a wildcard is not allowed.
        String wildcardedDomain = afterWildcard.substring(firstDotIndex + 1);
        String templateDomainSuffix =
                RegisteredDomain.from("z." + wildcardedDomain)
                        .filter(d -> d.type() == RegisteredDomain.Type.ICANN)
                        .map(RegisteredDomain::publicSuffix).orElse(null);
        if (templateDomainSuffix == null) {
            return false;   // skip check if not known public suffix
        }

        // Is it a top-level domain?
        return wildcardedDomain.equalsIgnoreCase(templateDomainSuffix);
    }

    /**
     * Returns true if name matches against template.<p>
     *
     * As per RFC 2830, section 3.6 -
     * The "*" wildcard character is allowed.  If present, it applies only
     * to the left-most name component.
     * E.g. *.bar.com would match a.bar.com, b.bar.com, etc. but not
     * bar.com.
     */
    private static boolean matchLeftmostWildcard(String name,
                                                 String template) {
        name = name.toLowerCase(Locale.ENGLISH);
        template = template.toLowerCase(Locale.ENGLISH);

        // Retrieve leftmost component
        int templateIdx = template.indexOf(".");
        int nameIdx = name.indexOf(".");

        if (templateIdx == -1)
            templateIdx = template.length();
        if (nameIdx == -1)
            nameIdx = name.length();

        if (matchWildCards(name.substring(0, nameIdx),
                template.substring(0, templateIdx))) {

            // match rest of the name
            return template.substring(templateIdx).equals(
                    name.substring(nameIdx));
        } else {
            return false;
        }
    }


    /**
     * Returns true if the name matches against the template that may
     * contain wildcard char * <p>
     */
    private static boolean matchWildCards(String name, String template) {

        int wildcardIdx = template.indexOf("*");
        if (wildcardIdx == -1)
            return name.equals(template);

        boolean isBeginning = true;
        String beforeWildcard;
        String afterWildcard = template;

        while (wildcardIdx != -1) {

            // match in sequence the non-wildcard chars in the template.
            beforeWildcard = afterWildcard.substring(0, wildcardIdx);
            afterWildcard = afterWildcard.substring(wildcardIdx + 1);

            int beforeStartIdx = name.indexOf(beforeWildcard);
            if ((beforeStartIdx == -1) ||
                    (isBeginning && beforeStartIdx != 0)) {
                return false;
            }
            isBeginning = false;

            // update the match scope
            name = name.substring(beforeStartIdx + beforeWildcard.length());
            wildcardIdx = afterWildcard.indexOf("*");
        }
        return name.endsWith(afterWildcard);
    }
}
