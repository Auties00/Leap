package it.auties.leap.server;

import java.io.IOException;

public class TestOpenSSL {
    public static void main(String[] args) throws IOException, InterruptedException {
        new ProcessBuilder()
                .command("openssl s_server -cipher ALL -accept 8080 -nocert".split(" "))
                .inheritIO()
                .start()
                .waitFor();
    }
}
