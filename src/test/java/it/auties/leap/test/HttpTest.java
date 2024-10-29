package it.auties.leap.test;

import it.auties.leap.http.HttpClient;
import it.auties.leap.http.HttpRequest;
import it.auties.leap.http.HttpResponse;
import org.junit.jupiter.api.Test;

import java.net.URI;

public class HttpTest {
    @Test
    public void testPlainDirect() {
        var request = HttpRequest.builder()
                .get()
                .uri(URI.create("http://api.ipify.org/"))
                .build();
        try(var client = new HttpClient()) {
            System.out.println(client.send(request, HttpResponse.Converter.ofString()).join());
        }
    }

    @Test
    public void testSecureDirect() {
        var request = HttpRequest.builder()
                .get()
                .uri(URI.create("https://api.ipify.org/"))
                .build();
        try(var client = new HttpClient()) {
            System.out.println(client.send(request, HttpResponse.Converter.ofString()).join());
        }
    }
}
