package it.auties.leap;

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
            System.out.println(client.sendAsync(request, HttpResponse.Converter.ofString()).join());
            System.out.println(client.sendAsync(request, HttpResponse.Converter.ofString()).join());
            System.out.println(client.sendAsync(request, HttpResponse.Converter.ofString()).join());
        }
        try(var client = new HttpClient()) {
            System.out.println(client.sendAsync(request, HttpResponse.Converter.ofString()).join());
            System.out.println(client.sendAsync(request, HttpResponse.Converter.ofString()).join());
            System.out.println(client.sendAsync(request, HttpResponse.Converter.ofString()).join());
        }
    }

    @Test
    public void testSecureDirect() {
        var request = HttpRequest.builder()
                .get()
                .uri(URI.create("https://api.ipify.org/"))
                .build();
        try(var client = new HttpClient()) {
            System.out.println(client.sendAsync(request, HttpResponse.Converter.ofString()).join());
        }
    }
}
