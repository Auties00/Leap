package it.auties.leap;

import it.auties.leap.tls.TlsHmacType;
import it.auties.leap.tls.hash.TlsHmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;

public class Ci {
    public static void main(String[] args) {
        for(var hash : TlsHmacType.values()) {
            if(hash != TlsHmacType.NULL) {
                test(hash);
            }
        }
    }

    private static void test(TlsHmacType tlsHmacType) {
        System.out.println(tlsHmacType);
        var message = new byte[8192];
        ThreadLocalRandom.current().nextBytes(message);
        var message1 = new byte[8192];
        ThreadLocalRandom.current().nextBytes(message1);
        var keyBytes = new byte[32];
        ThreadLocalRandom.current().nextBytes(keyBytes);
        var alg = tlsHmacType.name().replaceAll("_", "");
        var key = new SecretKeySpec(keyBytes, alg);
        try {
            var jmd = Mac.getInstance(alg);
            jmd.init(key);
            jmd.update(message);
            jmd.update(message1);
            System.out.println(HexFormat.of().formatHex(jmd.doFinal()));
        }catch (Throwable _) {

        }
        var cmd = TlsHmac.of(tlsHmacType);
        cmd.init(key);
        cmd.update(message);
        cmd.update(message1);
        System.out.println(HexFormat.of().formatHex(cmd.doFinal()));
    }
}
