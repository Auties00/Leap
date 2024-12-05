package it.auties.leap.tls.key;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsHashType;
import it.auties.leap.tls.TlsRecord;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.hash.TlsPrf;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.engine.TlsEngineMode;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.key.TlsKeyConstants.*;
import static it.auties.leap.tls.TlsRecord.*;

public record TlsSessionKeys(
        TlsMasterSecretKey masterSecretKey,

        SecretKey localMacKey,
        SecretKey remoteMacKey,

        SecretKey localCipherKey,
        SecretKey remoteCipherKey,

        byte[] localIv,
        byte[] remoteIv
) {
    public TlsSessionKeys {
        if((localCipherKey != null) ^ (remoteCipherKey != null)) {
            throw new IllegalArgumentException("Invalid session keys: local and remote cipher key have different states");
        }

        if((localIv != null) ^ (remoteIv != null)) {
            throw new IllegalArgumentException("Invalid session keys: local and remote iv have different states");
        }
    }

    public static TlsSessionKeys of(
            TlsEngineMode mode,
            TlsVersion version,
            TlsCipher cipher,
            TlsMasterSecretKey masterSecret,
            TlsRandomData localRandomData,
            TlsRandomData remoteRandomData
    ) {
        var clientRandom = switch (mode) {
            case CLIENT -> localRandomData.data();
            case SERVER -> remoteRandomData.data();
        };
        var serverRandom = switch (mode) {
            case SERVER -> localRandomData.data();
            case CLIENT -> remoteRandomData.data();
        };
        var macLength = cipher.hmac()
                .length();
        var expandedKeyLength = cipher.encryption()
                .expandedKeyLength()
                .orElse(-1);
        var keyLength = cipher.encryption()
                .cipherKeyLength();
        var ivLength = cipher.encryption().ivLength() - DYNAMIC_IV_LENGTH;

        var keyBlockLen = (macLength + keyLength + (expandedKeyLength != -1 ? 0 : ivLength)) << 2;
        var keyBlock = generateBlock(version, cipher, masterSecret.data(), clientRandom, serverRandom, keyBlockLen);

        var clientMacKey = macLength != 0 ? new SecretKeySpec(readBytes(keyBlock, macLength), "RAW") : null;
        var serverMacKey = macLength != 0 ? new SecretKeySpec(readBytes(keyBlock, macLength), "RAW") : null;

        if (cipher.encryption() == TlsCipher.Type.NULL) {
            return new TlsSessionKeys(
                    masterSecret,
                    clientMacKey,
                    serverMacKey,
                    null,
                    null,
                    null,
                    null
            );
        }

        var clientKeyBytes = readBytes(keyBlock, keyLength);
        var clientKey = new SecretKeySpec(clientKeyBytes, "AES");
        var serverKeyBytes = readBytes(keyBlock, keyLength);
        var serverKey = new SecretKeySpec(serverKeyBytes, "AES");

        if (expandedKeyLength == -1) {
            var clientIv = TlsRecord.readBytes(keyBlock, ivLength);
            var serverIv = TlsRecord.readBytes(keyBlock, ivLength);
            return new TlsSessionKeys(
                    masterSecret,
                    clientMacKey,
                    serverMacKey,
                    clientKey,
                    serverKey,
                    clientIv,
                    serverIv
            );
        }

        if(version == TlsVersion.SSL30) {
            var md5 = TlsHash.of(TlsHashType.MD5);
            md5.update(clientKeyBytes);
            md5.update(clientRandom);
            md5.update(serverRandom);
            var clientCipherKey = new SecretKeySpec(md5.digest(true, 0, expandedKeyLength), "AES");

            md5.update(serverKeyBytes);
            md5.update(serverRandom);
            md5.update(clientRandom);
            var serverCipherKey = new SecretKeySpec(md5.digest(true, 0, expandedKeyLength), "AES");

            if (ivLength == 0) {
                return new TlsSessionKeys(
                        masterSecret,
                        clientMacKey,
                        serverMacKey,
                        clientCipherKey,
                        serverCipherKey,
                        new byte[0],
                        new byte[0]
                );
            }

            md5.update(clientRandom);
            md5.update(serverRandom);
            var clientIv = md5.digest(true, 0, ivLength);

            md5.update(serverRandom);
            md5.update(clientRandom);
            var serverIv = md5.digest(true, 0, ivLength);

            return new TlsSessionKeys(
                    masterSecret,
                    clientMacKey,
                    serverMacKey,
                    clientCipherKey,
                    serverCipherKey,
                    clientIv,
                    serverIv
            );
        }

        if(version == TlsVersion.TLS10) {
            var seed = TlsPrf.seed(clientRandom, serverRandom);
            var clientCipherKey = new SecretKeySpec(TlsPrf.tls10Prf(clientKeyBytes, LABEL_CLIENT_WRITE_KEY, seed, expandedKeyLength), "AES");
            var serverCipherKey = new SecretKeySpec(TlsPrf.tls10Prf(serverKeyBytes, LABEL_SERVER_WRITE_KEY, seed, expandedKeyLength), "AES");

            if (ivLength == 0) {
                return new TlsSessionKeys(
                        masterSecret,
                        clientMacKey,
                        serverMacKey,
                        clientCipherKey,
                        serverCipherKey,
                        new byte[0],
                        new byte[0]
                );
            }

            var block = TlsPrf.tls10Prf(null, LABEL_IV_BLOCK, seed, ivLength << 1);
            var clientIv = Arrays.copyOf(block, ivLength);
            var serverIv = Arrays.copyOfRange(block, ivLength, ivLength << 2);
            return new TlsSessionKeys(
                    masterSecret,
                    clientMacKey,
                    serverMacKey,
                    clientCipherKey,
                    serverCipherKey,
                    clientIv,
                    serverIv
            );
        }

        throw new RuntimeException("TLS 1.1+ should not be negotiating exportable ciphersuites");
    }

    private static ByteBuffer generateBlock(TlsVersion version, TlsCipher cipher, byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, int keyBlockLen) {
        return switch (version) {
            case SSL30 -> {
                var md5 = TlsHash.of(TlsHashType.MD5);
                var sha = TlsHash.of(TlsHashType.SHA1);
                var keyBlock = new byte[keyBlockLen];
                var tmp = new byte[20];
                for (int i = 0, remaining = keyBlockLen; remaining > 0; i++, remaining -= 16) {
                    sha.update(SSL3_CONSTANT[i]);
                    sha.update(masterSecret);
                    sha.update(serverRandom);
                    sha.update(clientRandom);
                    sha.digest(tmp, 0, 20, true);

                    md5.update(masterSecret);
                    md5.update(tmp);

                    if (remaining >= 16) {
                        md5.digest(keyBlock, i << 4, 16, true);
                    } else {
                        md5.digest(tmp, 0, 16, true);
                        System.arraycopy(tmp, 0, keyBlock, i << 4, remaining);
                    }
                }
                yield ByteBuffer.wrap(keyBlock);
            }
            case TLS10, TLS11 -> {
                var seed = TlsPrf.seed(serverRandom, clientRandom);
                var result = TlsPrf.tls10Prf(
                        masterSecret,
                        LABEL_KEY_EXPANSION,
                        seed,
                        keyBlockLen
                );
                yield ByteBuffer.wrap(result);
            }
            default -> {
                var seed = TlsPrf.seed(serverRandom, clientRandom);
                var result = TlsPrf.tls12Prf(
                        masterSecret,
                        LABEL_KEY_EXPANSION,
                        seed,
                        keyBlockLen,
                        cipher.hash()
                );
                yield ByteBuffer.wrap(result);
            }
        };
    }

    public boolean hasCipher() {
        return localCipherKey != null && remoteCipherKey != null;
    }
}
