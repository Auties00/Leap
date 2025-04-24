package it.auties.leap.codegen;

import it.auties.leap.tls.hash.TlsHash;

import java.util.Arrays;

public class EmptyTest {
    public static void main(String[] args) {
        var digest = TlsHash.sha256();

        System.out.println(Arrays.toString( digest.digest(false)));
    }
}
