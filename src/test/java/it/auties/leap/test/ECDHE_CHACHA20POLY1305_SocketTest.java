
package it.auties.leap.test;

import it.auties.leap.http.exchange.serialization.AsyncHttpSerializer;
import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.context.TlsConfig;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ECDHE_CHACHA20POLY1305_SocketTest {
    public static void main(String[] args) throws IOException {
        // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        var ciphers = List.of(
                TlsCipher.ecdheEcdsaWithChacha20Poly1305Sha256()
        );
        var extensions = List.of(
                TlsExtension.serverNameIndication(),
                TlsExtension.ecPointFormats(),
                TlsExtension.supportedGroups(),
                TlsExtension.nextProtocolNegotiation(),
                TlsExtension.alpn(List.of("http/1.1")),
                TlsExtension.encryptThenMac(),
                TlsExtension.extendedMasterSecret(),
                TlsExtension.postHandshakeAuth(),
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
                .certificatesHandler(TlsCertificatesHandler.validate())
                .build();
        try (
                var socket = SocketClient.newBuilder()
                        .async(SocketProtocol.TCP)
                        .secure(tlsConfig)
                        .build()
        ) {
            socket.connect(new InetSocketAddress("api.ipify.org", 443)).join();
            var builder = "GET / HTTP/1.1\r\n" +
                    "Host: api.ipify.org\r\n" +
                    "Connection: close\r\n" +
                    "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0\r\n" +
                    "Accept: */*\r\n\r\n";

            socket.write(StandardCharsets.UTF_8.encode(builder)).join();
            new AsyncHttpSerializer<>(socket, Http).decode();
        }
    }
}