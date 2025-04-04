package it.auties.leap.test;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SSLSocketClientTLS13 {
    public static void main(String[] args) {
        // Replace with your server's address and port
        String serverAddress = "localhost"; // e.g., "localhost" or an IP
        int serverPort = 8082; // e.g., 443 or a custom port

        System.out.println("Attempting to connect to " + serverAddress + ":" + serverPort + " using TLS 1.3...");

        try {
            // 1. Get SSLContext instance specifically requesting TLSv1.3
            // Alternatively, use "TLS" and rely on setEnabledProtocols later for stricter control.
            // Using "TLSv1.3" signals intent but final negotiation depends on both sides.
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");

            // 2. Initialize SSLContext
            // Using null uses default KeyManager, TrustManager, and SecureRandom.
            // For production, you might need custom TrustManagers to validate server certs.
            sslContext.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            }, null); // Defaults are often sufficient for clients

            // 3. Get SSLSocketFactory from the context
            SSLSocketFactory factory = sslContext.getSocketFactory();

            // 4. Create SSLSocket
            // Use try-with-resources for automatic closing
            try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(serverAddress, serverPort)) {

                // 5. *** Crucial Step: Explicitly enable ONLY TLS 1.3 ***
                // This ensures that *only* TLS 1.3 will be negotiated.
                // If the server doesn't support it, the handshake will fail.
                sslSocket.setEnabledProtocols(new String[]{"TLSv1.3"});

                // (Optional) Print supported/enabled protocols and cipher suites for verification
                System.out.println("\n--- SSL/TLS Information ---");
                System.out.println("Supported Protocols: " + String.join(", ", sslSocket.getSupportedProtocols()));
                System.out.println("Enabled Protocols: " + String.join(", ", sslSocket.getEnabledProtocols()));
                System.out.println("Enabled Cipher Suites: " + String.join(", ", sslSocket.getEnabledCipherSuites()));
                System.out.println("Using Cipher Suite: " + sslSocket.getSession().getCipherSuite());
                System.out.println("Using Protocol: " + sslSocket.getSession().getProtocol());
                System.out.println("---------------------------\n");


                // Start handshake explicitly (optional, often done implicitly on first I/O)
                // sslSocket.startHandshake();
                // System.out.println("SSL Handshake successful.");

                // 6. Perform I/O operations
                // Use try-with-resources for automatic closing of streams
                try (PrintWriter out = new PrintWriter(sslSocket.getOutputStream(), true); // true for auto-flush
                     BufferedReader in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream())))
                {
                    // Send a message to the server
                    String messageToSend = "Hello Server from TLS 1.3 Client!";
                    System.out.println("Sending: " + messageToSend);
                    out.println(messageToSend);

                    // Read the response from the server
                    String serverResponse = in.readLine();
                    if (serverResponse != null) {
                        System.out.println("Received: " + serverResponse);
                    } else {
                        System.out.println("Server closed the connection without sending a response.");
                    }
                } // Streams are automatically closed here

            } // SSLSocket is automatically closed here
            System.out.println("Connection closed.");

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: TLSv1.3 protocol not supported by this Java runtime.");
            e.printStackTrace();
        } catch (KeyManagementException e) {
            System.err.println("Error initializing SSLContext (Key Management):");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Error during SSL/TLS connection or I/O:");
            // This catches UnknownHostException, ConnectException, SSLException (handshake failures), etc.
            e.printStackTrace();
        }
    }
}