package it.auties.leap;

import java.net.URI;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

public class TestClient {
    public static void main(String[] args) throws InterruptedException {
        var counter = new AtomicInteger(0);
        int val = 1000;
        var semaphore = new CountDownLatch(val);
        var time = System.currentTimeMillis();
        var request = HttpRequest.builder()
                .get()
                .uri(URI.create("https://api.ipify.org/"))
                .build();
        for (int i = 0; i < val; i++) {
            var config = new HttpClient.Configuration()
                    .proxy(URI.create("https://litease_%s-country-us:Sinan208@proxyus.rola.vip:1066/".formatted(ThreadLocalRandom.current().nextInt(1, 100_000))));
            var client = new HttpClient(config);
            client.sendAsync(request, HttpResponse.Converter.ofString()).whenCompleteAsync((result, error) -> {
                System.out.println(result + " - " + (error != null ? error.getMessage() : ""));
                System.out.println((counter.incrementAndGet() * 100 / val) + "% - " + (System.currentTimeMillis() - time) + "ms");
                semaphore.countDown();
                client.close();
            });
        }
        semaphore.await();
    }
}