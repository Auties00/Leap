
package it.auties.leap.test;

import it.auties.leap.http.async.AsyncHttpClient;
import it.auties.leap.http.config.HttpConfig;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.request.HttpRequest;
import it.auties.leap.tls.version.TlsVersion;

import java.net.URI;
import java.util.List;

public class ECDHE_CHACHA20POLY1305_SocketTest {
    public static void main(String[] args) throws Exception {
        var tlsConfig = HttpConfig.defaults()
                .tlsConfig()
                .withVersions(List.of(TlsVersion.TLS12));
        var httpConfig = HttpConfig.defaults()
                .withTlsConfig(tlsConfig);
        var client = AsyncHttpClient.newHTTPClient(httpConfig);
        {
            var request = HttpRequest.newBuilder()
                    .get()
                    .uri(URI.create("https://api.ipify.org/"))
                    .header("Connection", "Keep-Alive")
                    .build();
            client.send(request, HttpBodyDeserializer.ofString())
                    .thenAccept(System.out::println);
        }

        client.close();
    }
}