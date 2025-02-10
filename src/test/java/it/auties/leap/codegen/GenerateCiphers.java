
package it.auties.leap.codegen;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

public class GenerateCiphers {
    public static void main(String[] args) throws IOException {
        var ciphersResponse = URI.create("https://ciphersuite.info/api/cs/")
                .toURL()
                .openConnection()
                .getInputStream()
                .readAllBytes();

        var mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        var parsedResponse = mapper.readValue(ciphersResponse, Response.class);
        for(var cipherMap : parsedResponse.ciphers()) {
            var cipherEntry = cipherMap.firstEntry();
            var cipherName = cipherEntry.getKey();
            var cipherValue = cipherEntry.getValue();
            System.out.printf(
                    "private static final TlsCipher %s = new TlsCipher(%s, TlsKeyExchangeType.%s(), TlsAuthType.%s(), Type.%s(), TlsHashType.%s(), List.of(%s), %s);%n",
                    cipherName.toUpperCase(),
                    cipherValue.id(),
                    snakeToCamel(cipherValue.keyExchange()),
                    snakeToCamel(cipherValue.auth()),
                    snakeToCamel(cipherValue.enc()),
                    snakeToCamel(cipherValue.hash()),
                    cipherValue.tlsVersions()
                            .stream()
                            .map(entry -> "TlsVersion." + entry.name())
                            .collect(Collectors.joining(", ")),
                    cipherValue.recommended()
            );
        }
        System.out.println();
        var values = new ArrayList<String>();
        var secure = new ArrayList<String>();
        var cases = new ArrayList<String>();
        for(var cipherMap : parsedResponse.ciphers()) {
            for(var cipherEntry : cipherMap.entrySet()) {
                var cipherName = cipherEntry.getKey();
                System.out.printf(
                        """
                        public static TlsCipher %s() {
                            return %s;
                        }
                        """,
                        snakeToCamel(cipherName.toLowerCase().replaceFirst("tls_", "")),
                        cipherName.toUpperCase()
                );
                cases.add("         case %s -> Optional.of(%s);".formatted(
                        cipherEntry.getValue().id(),
                        cipherName.toUpperCase()
                ));
                values.add("    " + cipherName.toUpperCase());
                if(cipherEntry.getValue().recommended()) {
                    secure.add("    " + cipherName.toUpperCase());
                }
                System.out.println();
            }
        }
        System.out.printf(
                """
                public static Optional<TlsCipher> of(int id) {
                    return switch(id) {
                %s
                        default -> Optional.empty();
                    };
                }
                """,
                String.join("\n", cases)
        );
        System.out.println();
        System.out.printf(
                """
                private static final List<TlsCipher> ALL = List.of(
                %s
                );
                """,
                String.join(",\n", values)
        );
        System.out.println();
        System.out.printf(
                """
                private static final List<TlsCipher> SECURE = List.of(
                %s
                );
                """,
                String.join(",\n", secure)
        );
    }

    // https://stackoverflow.com/a/77849581/10180192
    private static String snakeToCamel(String input) {
        if (!input.contains("_")){
            return input.toLowerCase(Locale.ROOT);
        }

        var sb = new StringBuilder();
        var words = input.split("_");
        for (var j = 0; j < words.length; j++) {
            for (var i = 0; i < words[j].length(); i++) {
                var letter = words[j].charAt(i);
                if (j != 0 && i == 0) {
                    sb.append(Character.toUpperCase(letter));
                } else {
                    sb.append(letter);
                }
            }
        }
        return sb.toString();
    }

    private record Response(
            @JsonProperty("ciphersuites") List<LinkedHashMap<String, Cipher>> ciphers
    ) {

    }


    private record Cipher(
            String id,
            String keyExchange,
            String auth,
            String enc,
            String hash,
            boolean recommended,
            List<TlsVersion> tlsVersions
    ) {
        @JsonCreator
        private Cipher(
                @JsonProperty("hex_byte_1")
                String hexBytes1,
                @JsonProperty("hex_byte_2")
                String hexBytes2,
                @JsonProperty("kex_algorithm")
                String keyExchange,
                @JsonProperty("auth_algorithm")
                String auth,
                @JsonProperty("enc_algorithm")
                String enc,
                @JsonProperty("hash_algorithm")
                String hash,
                @JsonProperty("security")
                String security,
                @JsonProperty("tls_version")
                List<String> tlsVersions
        ) {
            this(
                    "0x" + hexBytes1.substring(2) + hexBytes2.substring(2),
                    standardize(keyExchange),
                    standardize(auth),
                    standardize(enc),
                    standardize(hash),
                    security.equals("secure"),
                    tlsVersions.stream()
                            .map(TlsVersion::of)
                            .flatMap(Optional::stream)
                            .toList()
            );
        }

        private static String standardize(String keyExchange) {
            if(keyExchange.equals("-")) {
                return "NULL";
            }

            var result = keyExchange.replaceAll(" ", "_").toUpperCase();
            if(Character.isDigit(result.charAt(0))) {
                return "_" + result;
            }

            return result;
        }
    }
}

