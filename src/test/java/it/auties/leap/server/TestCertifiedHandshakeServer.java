package it.auties.leap.server;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

public class TestCertifiedHandshakeServer {
    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (var trustStoreInput = Files.newInputStream(Path.of(ClassLoader.getSystemResource("keystore.jks").toURI()))) {
            trustStore.load(trustStoreInput, "password".toCharArray());
        }

        // Initialize the KeyManagerFactory with the keystore
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(trustStore, "password".toCharArray());

        // Initialize the TrustManagerFactory with the truststore
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        // Create the SSLContext using the key and trust managers
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        // Create the SSLServerSocketFactory
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        // Create the SSLServerSocket
        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(PORT);

        // Require client authentication
        // serverSocket.setNeedClientAuth(true);

        System.out.println("SSL Server started. Waiting for clients...");

        while (true) {
            try (SSLSocket clientSocket = (SSLSocket) serverSocket.accept()) {
                System.out.println("Client connected.");
                handleClient(clientSocket);
            } catch (Exception e) {
                System.err.println("Error handling client: " + e.getMessage());
            }
        }
    }

    private static void handleClient(SSLSocket clientSocket) throws IOException {
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
        }
    }
}
