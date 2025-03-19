/*
 * Copyright (c) 2002, 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package it.auties.leap.tls.util.sun;

import javax.net.ssl.SNIHostName;
import java.net.IDN;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.Normalizer;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

public final class HostnameChecker {
    private static final int ALTNAME_DNS = 2;
    private static final int ALTNAME_IP  = 7;

    public static void match(String expectedName, X509Certificate cert, boolean chainsToPublicCA) throws CertificateException {
        if (expectedName == null) {
            throw new CertificateException("Hostname or IP address is " + "undefined.");
        }

        if (IPAddressUtil.isIPv4LiteralAddress(expectedName) || IPAddressUtil.isIPv6LiteralAddress(expectedName)) {
            matchIP(expectedName, cert);
        } else {
            matchDNS(expectedName, cert, chainsToPublicCA);
        }
    }

    private static void matchIP(String expectedIP, X509Certificate cert) throws CertificateException {
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

    private static void matchDNS(String expectedName, X509Certificate cert, boolean chainsToPublicCA) throws CertificateException {
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

    private static boolean isMatched(String name, String template, boolean chainsToPublicCA) {
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
    private static boolean matchLeftmostWildcard(String name, String template) {
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