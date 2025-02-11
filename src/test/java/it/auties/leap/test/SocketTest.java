
package it.auties.leap.test;

import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.TlsConfig;
import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SocketTest {
    public static void main(String[] args) throws IOException {
        // ECDHE-ECDSA-AES256-CCM
        var ciphers = List.of(
                TlsCipher.chacha20Poly1305Sha256(),
                TlsCipher.aes256GcmSha384(),
                TlsCipher.chacha20Poly1305Sha256(),
                TlsCipher.aes128GcmSha256(),
                TlsCipher.ecdheEcdsaWithAes256GcmSha384(),
                TlsCipher.ecdheRsaWithAes256GcmSha384(),
                TlsCipher.dheRsaWithAes256GcmSha384(),
                TlsCipher.ecdheEcdsaWithChacha20Poly1305Sha256(),
                TlsCipher.ecdheRsaWithChacha20Poly1305Sha256(),
                TlsCipher.dheRsaWithChacha20Poly1305Sha256(),
                TlsCipher.ecdheEcdsaWithAes128GcmSha256(),
                TlsCipher.ecdheRsaWithAes128GcmSha256(),
                TlsCipher.dheRsaWithAes128GcmSha256(),
                TlsCipher.ecdheEcdsaWithAes256CbcSha384(),
                TlsCipher.ecdheRsaWithAes256CbcSha384(),
                TlsCipher.dheRsaWithAes256CbcSha256(),
                TlsCipher.ecdheEcdsaWithAes128CbcSha256(),
                TlsCipher.ecdheRsaWithAes128CbcSha256(),
                TlsCipher.dheRsaWithAes128CbcSha256(),
                TlsCipher.ecdheEcdsaWithAes256CbcSha(),
                TlsCipher.ecdheRsaWithAes256CbcSha(),
                TlsCipher.dheRsaWithAes256CbcSha(),
                TlsCipher.ecdheEcdsaWithAes128CbcSha(),
                TlsCipher.ecdheRsaWithAes128CbcSha(),
                TlsCipher.dheRsaWithAes128CbcSha(),
                TlsCipher.rsaWithAes256GcmSha384(),
                TlsCipher.rsaWithAes128GcmSha256(),
                TlsCipher.rsaWithAes256CbcSha256(),
                TlsCipher.rsaWithAes128CbcSha256(),
                TlsCipher.rsaWithAes256CbcSha(),
                TlsCipher.rsaWithAes128CbcSha()
        );
        var extensions = List.of(
                TlsExtension.serverNameIndication(),
                TlsExtension.ecPointFormats(),
                TlsExtension.supportedGroups(),
                TlsExtension.nextProtocolNegotiation(),
                TlsExtension.alpn(List.of("http/1.1")),
                TlsExtension.encryptThenMac(),
                TlsExtension.extendedMasterSecret(),
                // TlsExtension.postHandshakeAuth(),
                TlsExtension.signatureAlgorithms(),
                TlsExtension.supportedVersions(),
                TlsExtension.pskExchangeModes(List.of(TlsPSKExchangeMode.pskDheKe())),
                TlsExtension.keyShare(),
                TlsExtension.padding(517)
        );
        var compressions = List.of(
                TlsCompression.none()
        );
        var tlsConfig = TlsConfig.newBuilder()
                .version(TlsVersion.TLS12)
                .ciphers(ciphers)
                .extensions(extensions)
                .compressions(compressions)
                .certificatesHandler(TlsCertificatesHandler.ignore())
                .build();
        try (
                var socket = SocketClient.newBuilder()
                        .async(SocketProtocol.TCP)
                        .secure(tlsConfig)
                        .build()
        ) {
            socket.connect(new InetSocketAddress("localhost", 8080)).join();
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