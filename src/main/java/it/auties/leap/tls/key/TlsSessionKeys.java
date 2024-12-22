package it.auties.leap.tls.key;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsPRF;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

import static it.auties.leap.tls.util.BufferHelper.readBytes;
import static it.auties.leap.tls.key.TlsKeyConstants.*;

public final class TlsSessionKeys {
    private final TlsMasterSecretKey masterSecretKey;
    private final byte[] localMacKey;
    private final byte[] remoteMacKey;
    private final byte[] localCipherKey;
    private final byte[] remoteCipherKey;
    private final byte[] localIv;
    private final byte[] remoteIv;
    private TlsSessionKeys(TlsMasterSecretKey masterSecretKey, byte[] localMacKey, byte[] remoteMacKey, byte[] localCipherKey, byte[] remoteCipherKey, byte[] localIv, byte[] remoteIv) {
        if ((localCipherKey != null) ^ (remoteCipherKey != null)) {
            throw new IllegalArgumentException("Invalid session keys: local and remote cipher key have different states");
        }

        if ((localIv != null) ^ (remoteIv != null)) {
            throw new IllegalArgumentException("Invalid session keys: local and remote iv have different states");
        }

        this.masterSecretKey = masterSecretKey;
        this.localMacKey = localMacKey;
        this.remoteMacKey = remoteMacKey;
        this.localCipherKey = localCipherKey;
        this.remoteCipherKey = remoteCipherKey;
        this.localIv = localIv;
        this.remoteIv = remoteIv;
    }

    public static TlsSessionKeys of(
            TlsMode mode,
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
        var macLength = cipher.hashSupplier()
                .get()
                .length();
        var expandedKeyLength = cipher.factory()
                .expandedKeyLength()
                .orElse(-1);
        var keyLength = cipher.factory()
                .cipherKeyLength();
        var ivLength = cipher.factory().ivLength() - DYNAMIC_IV_LENGTH;

        var keyBlockLen = (macLength + keyLength + (expandedKeyLength != -1 ? 0 : ivLength)) << 2;
        var keyBlock = generateBlock(version, cipher, masterSecret.data(), clientRandom, serverRandom, keyBlockLen);

        var clientMacKey = macLength != 0 ? readBytes(keyBlock, macLength) : null;
        var serverMacKey = macLength != 0 ? readBytes(keyBlock, macLength) : null;

        if (cipher.factory().cipherKeyLength() == 0) {
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
        var serverKeyBytes = readBytes(keyBlock, keyLength);

        if (expandedKeyLength == -1) {
            var clientIv = readBytes(keyBlock, ivLength);
            var serverIv = readBytes(keyBlock, ivLength);
            return new TlsSessionKeys(
                    masterSecret,
                    clientMacKey,
                    serverMacKey,
                    clientKeyBytes,
                    serverKeyBytes,
                    clientIv,
                    serverIv
            );
        }

        if (version == TlsVersion.SSL30) {
            var md5 = TlsHash.md5();
            md5.update(clientKeyBytes);
            md5.update(clientRandom);
            md5.update(serverRandom);
            var clientCipherKey = md5.digest(true, 0, expandedKeyLength);

            md5.update(serverKeyBytes);
            md5.update(serverRandom);
            md5.update(clientRandom);
            var serverCipherKey = md5.digest(true, 0, expandedKeyLength);

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

        if (version == TlsVersion.TLS10) {
            var seed = TlsPRF.seed(clientRandom, serverRandom);
            var clientCipherKey = TlsPRF.tls10Prf(clientKeyBytes, LABEL_CLIENT_WRITE_KEY, seed, expandedKeyLength);
            var serverCipherKey = TlsPRF.tls10Prf(serverKeyBytes, LABEL_SERVER_WRITE_KEY, seed, expandedKeyLength);

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

            var block = TlsPRF.tls10Prf(null, LABEL_IV_BLOCK, seed, ivLength << 1);
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
                var md5 = TlsHash.md5();
                var sha = TlsHash.sha1();
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
                var seed = TlsPRF.seed(serverRandom, clientRandom);
                var result = TlsPRF.tls10Prf(
                        masterSecret,
                        LABEL_KEY_EXPANSION,
                        seed,
                        keyBlockLen
                );
                yield ByteBuffer.wrap(result);
            }
            default -> {
                var seed = TlsPRF.seed(serverRandom, clientRandom);
                var result = TlsPRF.tls12Prf(
                        masterSecret,
                        LABEL_KEY_EXPANSION,
                        seed,
                        keyBlockLen,
                        cipher.hashSupplier().get()
                );
                yield ByteBuffer.wrap(result);
            }
        };
    }

    public boolean hasCipher() {
        return localCipherKey != null && remoteCipherKey != null;
    }

    public TlsMasterSecretKey masterSecretKey() {
        return masterSecretKey;
    }

    public byte[] localMacKey() {
        return localMacKey;
    }

    public byte[] remoteMacKey() {
        return remoteMacKey;
    }

    public byte[] localCipherKey() {
        return localCipherKey;
    }

    public byte[] remoteCipherKey() {
        return remoteCipherKey;
    }

    public byte[] localIv() {
        return localIv;
    }

    public byte[] remoteIv() {
        return remoteIv;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (TlsSessionKeys) obj;
        return Objects.equals(this.masterSecretKey, that.masterSecretKey) &&
                Arrays.equals(this.localMacKey, that.localMacKey) &&
                Arrays.equals(this.remoteMacKey, that.remoteMacKey) &&
                Arrays.equals(this.localCipherKey, that.localCipherKey) &&
                Arrays.equals(this.remoteCipherKey, that.remoteCipherKey) &&
                Arrays.equals(this.localIv, that.localIv) &&
                Arrays.equals(this.remoteIv, that.remoteIv);
    }

    @Override
    public int hashCode() {
        return Objects.hash(masterSecretKey, Arrays.hashCode(localMacKey), Arrays.hashCode(remoteMacKey), Arrays.hashCode(localCipherKey), Arrays.hashCode(remoteCipherKey), Arrays.hashCode(localIv), Arrays.hashCode(remoteIv));
    }

    @Override
    public String toString() {
        return "TlsSessionKeys[" +
                "masterSecretKey=" + masterSecretKey + ", " +
                "localMacKey=" + Arrays.toString(localMacKey) + ", " +
                "remoteMacKey=" + Arrays.toString(remoteMacKey) + ", " +
                "localCipherKey=" + Arrays.toString(localCipherKey) + ", " +
                "remoteCipherKey=" + Arrays.toString(remoteCipherKey) + ", " +
                "localIv=" + Arrays.toString(localIv) + ", " +
                "remoteIv=" + Arrays.toString(remoteIv) + ']';
    }
}
