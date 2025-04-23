package it.auties.leap.tls.group;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

public final class TlsSupportedGroupKeys {
    private final TlsSupportedGroup group;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    private TlsSupportedGroupKeys(TlsSupportedGroup group, PublicKey publicKey, PrivateKey privateKey) {
        this.group = group;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public static TlsSupportedGroupKeys of(TlsSupportedGroup group, KeyPair keyPair) {
        return new TlsSupportedGroupKeys(group, keyPair.getPublic(), keyPair.getPrivate());
    }

    public static TlsSupportedGroupKeys of(TlsSupportedGroup group, PublicKey publicKey, PrivateKey privateKey) {
        return new TlsSupportedGroupKeys(group, publicKey, privateKey);
    }

    public static TlsSupportedGroupKeys of(TlsSupportedGroup group, PublicKey publicKey) {
        return new TlsSupportedGroupKeys(group, publicKey, null);
    }

    public TlsSupportedGroup group() {
        return group;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    public Optional<PrivateKey> privateKey() {
        return Optional.ofNullable(privateKey);
    }
}
