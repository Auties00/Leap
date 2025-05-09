
package it.auties.leap.test;

import it.auties.leap.http.async.AsyncHttpClient;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.request.HttpRequest;

import java.net.URI;

public class HTTPS_SocketTest {
    public static void main(String[] args) throws Exception {
        var client = AsyncHttpClient.newHTTPClient();
        {
            var request = HttpRequest.builder()
                    .get()
                    .uri(URI.create("https://api.ipify.org/"))
                    .header("Connection", "Keep-Alive")
                    .build();
            client.send(request, HttpBodyDeserializer.ofString())
                    .thenAccept(System.out::println)
                    .join();
        }

        client.close();
    }
}