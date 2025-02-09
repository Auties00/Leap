/*
package it.auties.leap.test;

import it.auties.leap.http.HttpResponseHandler;
import it.auties.leap.http.client.HttpClient;
import it.auties.leap.http.HttpConfig;
import it.auties.leap.http.HttpRequest;

import java.net.URI;

public class HttpTest {
    public static void main(String[] args) {
        var tlsConfig = HttpConfig.defaultTlsConfigBuilder()

                .build();
        var httpConfig = HttpConfig.builder()
                .tlsConfig(tlsConfig)
                .build();
        var request = HttpRequest.newBuilder()
                .get()
                .uri(URI.create("https://api.ipify.org/"))
                .build();
        try(var client = new HttpClient(httpConfig)) {
            System.out.println(client.send(request, HttpResponseHandler.ofString()).join());
        }
    }
}

 */