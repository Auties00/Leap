
package it.auties.leap.test;

import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.ciphersuite.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.supplemental.TlsName;
import it.auties.leap.tls.psk.TlsPskExchangeMode;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class DHE_CHACHA20POLY1305_SocketTest {
    public static void main(String[] args) throws IOException {
        // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        var ciphers = List.of(
                TlsCipherSuite.dheRsaWithChacha20Poly1305Sha256()
        );
        var extensions = List.of(
                TlsExtension.serverNameIndication(TlsName.Type.HOST_NAME),
                TlsExtension.ecPointFormats(),
                TlsExtension.supportedGroups(),
                TlsExtension.nextProtocolNegotiation(),
                TlsExtension.encryptThenMac(),
                TlsExtension.extendedMasterSecret(),
                // TlsExtension.postHandshakeAuth(),
                TlsExtension.signatureAlgorithms(),
                TlsExtension.supportedVersions(),
                TlsExtension.pskExchangeModes(List.of(TlsPskExchangeMode.pskDheKe())),
                TlsExtension.keyShare(),
                TlsExtension.padding(517)
        );
        var compressions = List.of(
                TlsCompression.none()
        );
        var tlsConfig = TlsContext.clientBuilder()
                .versions(List.of(TlsVersion.TLS12))
                .ciphers(ciphers)
                .extensions(extensions)
                .compressions(compressions)
                .certificateValidator(TlsCertificateValidator.discard())
                .build();
        try (
                var socket = SocketClient.builder()
                        .async(SocketProtocol.TCP)
                        .secure(tlsConfig)
                        .build()
        ) {
            socket.connect(new InetSocketAddress("localhost", 8082)).join();
            {
                var message = ByteBuffer.allocate(1024);
                socket.read(message).join();
                System.out.print(StandardCharsets.UTF_8.decode(message));
            }
            {
                socket.write(StandardCharsets.UTF_8.encode("Hello World\n")).join();
                var message1 = ByteBuffer.allocate(1024);
                socket.read(message1).join();
                System.out.print(StandardCharsets.UTF_8.decode(message1));
            }
            {
                socket.write(StandardCharsets.UTF_8.encode("Hello World123\n")).join();
                var message1 = ByteBuffer.allocate(1024);
                socket.read(message1).join();
                System.out.print(StandardCharsets.UTF_8.decode(message1));
            }
        }
    }
}