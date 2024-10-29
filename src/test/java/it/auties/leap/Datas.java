package it.auties.leap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

// 0xC034: "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
public class Datas {
    public static void main(String[] args) throws Exception  {
        var allLines = Files.readAllLines(Path.of(ClassLoader.getSystemResource("data.txt").toURI()));
        var later = new ArrayList<>();
        for(var line : allLines) {
            try {
                var split = line.split(": ");
                var id = split[0];
                var name = split[1].substring(1, split[1].length() - 2);
                var split1 = name.split("_WITH_");
                var key = split1[0].split("_", 2)[1];
                var enc = split1[1].substring(0, split1[1].lastIndexOf("_"));
                var hash = split1[1].substring(split1[1].lastIndexOf("_") + 1);
                // int id, KeyExchange keyExchange, Encryption encryption, Hash hash, TlsVersion version)
                System.out.printf("private static final TlsCipher %s = new TlsCipher(%s, KeyExchange.%s, Encryption.%s, Hash.%s, TlsVersion.TLS13);%n", name, id, key.toUpperCase(), enc.toUpperCase(), hash.toUpperCase());
            }catch (Throwable throwable) {
                later.add(line);
            }
        }
        System.out.println();
        for (Object o : later) {
            System.out.println(o);
        }
    }
}
