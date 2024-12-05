package it.auties.leap.test;

import it.auties.leap.http.HttpClient;
import it.auties.leap.http.HttpConfig;
import it.auties.leap.http.HttpRequest;
import it.auties.leap.http.HttpResponse;
import it.auties.leap.tls.TlsCipher;

import java.net.URI;
import java.util.List;

public class HttpTest {
    public static void main(String[] args) {
        var tlsConfig = HttpConfig.defaultTlsConfigBuilder()
                .ciphers(List.of(        TlsCipher.ecdheEcdsaWithAes256Ccm()))
                .build();
        var httpConfig = HttpConfig.builder()
                .tlsConfig(tlsConfig)
                .build();
        var request = HttpRequest.builder()
                .get()
                .uri(URI.create("https://api.ipify.org/"))
                .build();
        try(var client = new HttpClient(httpConfig)) {
            System.out.println(client.send(request, HttpResponse.Converter.ofString()).join());
        }
    }
}
