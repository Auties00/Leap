package it.auties.leap.codegen;

import it.auties.leap.tls.util.KeyUtils;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class Test {
    public static void main(String[] args) throws Throwable {
        var key = new byte[32];
        ThreadLocalRandom.current().nextBytes(key);
        var wrapped = KeyUtils.fromUnsignedLittleEndianBytes(key);
        var result = KeyUtils.toUnsignedLittleEndianBytes(wrapped);
        System.out.println(Arrays.toString(key));
        System.out.println(Arrays.toString(result));
    }
}
