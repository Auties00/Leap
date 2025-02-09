
package it.auties.leap.test;

import it.auties.leap.http.HttpConfig;
import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class SocketTest {
    public static void main(String[] args) throws IOException {
        // ECDHE-ECDSA-AES256-CCM
        var tlsConfig = HttpConfig.defaultTlsConfigBuilder()
                .version(TlsVersion.TLS12)
                .certificatesHandler(TlsCertificatesHandler.ignore())
                .build();
        try (
                var socket = SocketClient.newBuilder()
                        .async(SocketProtocol.tcp())
                        .secure(tlsConfig)
                        .build()
        ) {
            socket.connect(new InetSocketAddress("localhost", 4433)).join();
            var message = ByteBuffer.allocate(1024);
            socket.read(message).join();
            System.out.println(StandardCharsets.UTF_8.decode(message));
            {
                socket.write(StandardCharsets.UTF_8.encode("Hello World\n")).join();
                var message1 = ByteBuffer.allocate(1024);
                socket.read(message1).join();
                System.out.println(StandardCharsets.UTF_8.decode(message1));
            }
            {
                socket.write(StandardCharsets.UTF_8.encode("Hello World123\n")).join();
                var message1 = ByteBuffer.allocate(1024);
                socket.read(message1).join();
                System.out.println(StandardCharsets.UTF_8.decode(message1));
            }
        }
    }
}