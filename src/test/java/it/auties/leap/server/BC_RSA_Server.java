package it.auties.leap.server;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class BC_RSA_Server {
    public static void main(String[] args) throws Exception {
        System.setProperty("org.bouncycastle.jsse.level", "FINEST");
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());

        // Generate an RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Create a self-signed certificate (valid for one year)
        X500Name issuer = new X500Name("CN=RandomCert");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                issuer,
                keyPair.getPublic()
        );
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);

        // Create a KeyStore and load the certificate and private key
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        String alias = "RSA_CERT";
        char[] password = "password".toCharArray();
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, new X509Certificate[]{certificate});

        // Initialize a KeyManagerFactory with the KeyStore
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", "BCJSSE");
        kmf.init(keyStore, password);

        // Initialize the TrustManagerFactory
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        // Create and initialize the SSLContext using the BCJSSE provider
        SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");
        sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        // Create an SSLServerSocket and configure the cipher suite
        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        try (SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(8082)) {
            serverSocket.setEnabledCipherSuites(new String[] {
                    "TLS_RSA_WITH_AES_128_CBC_SHA256"
            });

            System.out.println("TLS server started on port 443, waiting for connections...");

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                new Thread(() -> handleClient(clientSocket)).start();
            }
        }
    }

    private static void handleClient(SSLSocket clientSocket) {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)
        ) {
            System.out.println("Sending message...");
            out.println("Welcome to the server!");

            String clientMessage;
            while ((clientMessage = in.readLine()) != null) {
                System.out.println("Received: " + clientMessage);
                out.println("Echo: " + clientMessage);
            }
        } catch (Throwable throwable) {
            System.err.println("Cannot handle connection: " + throwable.getLocalizedMessage());
        }
    }
}
