package it.auties.leap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ParseGostCertificate {
    public static void main(String[] args) throws Exception {
        // 1. Add the Bouncy Castle Provider (assuming you have Bouncy Castle in your classpath)
        Security.addProvider(new BouncyCastleProvider());

        // 2. Your GOST certificate in PEM format (as a String)
        String gostCertPEM = """
                -----BEGIN CERTIFICATE-----
                MIIB2TCCAY+gAwIBAgIEUqC2IzAMBggqhQMHAQECAgUAMBkxFzAVBgNVBAMMDkdP
                U1QgU2VsZi1TaWduZWQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAZ
                MRcwFQYDVQQDDA5HT1NUIFNlbGYtU2lnbmVkMFkwEwYHKoUDAgIjAQQEBgUrgQQI
                AwIBARobBgcqhQMCAiMBBgUrgQQIABgEBkGNNi8txOSt4N74LbfmF52FvRLJ04iV
                LRutZsMtwI5xu2seV0UeFWhZ2P2ljGJxCkkz8NBzKlJlgnZTfN7IygbMBkGA1UdDgQSBBCTgEDtoC7biJsFck60ZpqHBkml7jAP
                BgNVHRMBAf8EBTADAQH/MAwGCCqFAwcBAQICBQADSQAwRgIhAKq0+qTqpt1lMz94
                38XsDdCRpeF5xUAv9AbLtbCbRItTAiEAvmvrsrxEjgiYtRmG3RMNyn+pZgeuOH2y
                bB8qX3Uusbc=
                -----END CERTIFICATE-----
                """.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "")
                .replace(" ", "");

        // 3. Convert PEM to an InputStream
        ByteArrayInputStream inputStream = new ByteArrayInputStream(
            gostCertPEM.getBytes(StandardCharsets.US_ASCII)
        );

        // 4. Get a CertificateFactory instance for "X.509" with BouncyCastle provider
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // 5. Generate the certificate
        Certificate certificate = certificateFactory.generateCertificate(inputStream);

        // 6. (Optional) If you want X.509-specific methods:
        X509Certificate x509Cert = (X509Certificate) certificate;

        // 7. Use the certificate (e.g., print some info)
        System.out.println("Subject: " + x509Cert.getSubjectDN());
        System.out.println("Issuer: " + x509Cert.getIssuerDN());
        System.out.println("Not Before: " + x509Cert.getNotBefore());
        System.out.println("Not After : " + x509Cert.getNotAfter());
        System.out.println("Signature Algorithm: " + x509Cert.getSigAlgName());
        System.out.println("Public Key Algorithm: " + x509Cert.getPublicKey().getAlgorithm());
    }
}
