package it.auties.leap.integrity;

import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
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
    public static void main(String[] args) throws Throwable {
        for(var hashFactory : HASH_FACTORIES.entrySet()) {
            test(hashFactory.getKey(), hashFactory.getValue().newHash());
        }
    }

    private static void test(String name, TlsHash lmd) throws Throwable {
        var message = new byte[8197];
        ThreadLocalRandom.current().nextBytes(message);
        var message1 = new byte[8197];
        ThreadLocalRandom.current().nextBytes(message1);
        var jmd = MessageDigest.getInstance(name);
        jmd.update(message);
        jmd.update(message1);
        var jmdResult = jmd.digest();
        var message3 = ByteBuffer.wrap(message);
        lmd.update(message3);
        if(message3.hasRemaining()) {
            throw new NullPointerException();
        }
        var message4 = ByteBuffer.wrap(message1);
        lmd.update(message4);
        if(message4.hasRemaining()) {
            throw new NullPointerException();
        }
        var cmdResult = lmd.digest(true);
        if(!Arrays.equals(jmdResult, cmdResult)) {
            throw new NullPointerException();
        }
    }
}
