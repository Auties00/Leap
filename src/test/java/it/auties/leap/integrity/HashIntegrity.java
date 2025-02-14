package it.auties.leap.integrity;

import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.Security;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

public class HashIntegrity {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Map<String, TlsHashFactory> HASH_FACTORIES = Map.of(
            "SHA1", TlsHashFactory.sha1(),
            "SHA256", TlsHashFactory.sha256(),
            "SHA384", TlsHashFactory.sha384(),
            "MD5", TlsHashFactory.md5(),
            "SM3", TlsHashFactory.sm3(),
            "GOST3411-2012-256", TlsHashFactory.gostr341112_256()
    );
    public static void main(String[] args) {
        for(var hashFactory : HASH_FACTORIES.entrySet()) {
            test(hashFactory.getKey(), hashFactory.getValue().newHash());
        }
    }

    private static void test(String name, TlsHash cmd) {
        System.out.println(name);
        var message = new byte[8192];
        ThreadLocalRandom.current().nextBytes(message);
        var message1 = new byte[8192];
        ThreadLocalRandom.current().nextBytes(message1);
        try {
            var jmd = MessageDigest.getInstance(name);
            jmd.update(message);
            jmd.update(message1);
            System.out.println(HexFormat.of().formatHex(jmd.digest()));
        }catch (Throwable e) {
            System.err.println(e.getMessage());
        }
        cmd.update(message);
        cmd.update(message1);
        System.out.println(HexFormat.of().formatHex(cmd.digest(true)));
        System.out.println();
    }
}
