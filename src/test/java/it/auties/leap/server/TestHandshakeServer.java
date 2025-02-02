package it.auties.leap.server;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

public class TestHandshakeServer {
    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {
        // Create the SSLContext using the key and trust managers
        SSLContext sslContext = SSLContext.getInstance("TLS12");
        sslContext.init(null, null, null);

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
