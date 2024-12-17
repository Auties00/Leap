package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.client.DhClientKeyExchange;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsKeyPair;
import it.auties.leap.tls.key.TlsSupportedGroup;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;

import static it.auties.leap.tls.BufferHelper.*;

final class DheServerKeyExchange extends TlsKeyExchangeType.TlsServerKeyExchange {
    private static final int COMPONENT_LENGTH = 32;

    private final TlsKeyPair keyPair;

    DheServerKeyExchange(TlsVersion version, TlsSupportedGroup group) {
        super(version, group);
        this.keyPair = group.generateKeyPair(version);
    }

    DheServerKeyExchange(ByteBuffer buffer) {
        super(buffer);
        try {
            var keyFactory = KeyFactory.getInstance("DH");
            var p = readBytesLittleEndian16(buffer);
            var g = readBytesLittleEndian16(buffer);
            var y = readBytesLittleEndian16(buffer);
            var dhPubKeySpecs = new DHPublicKeySpec(
                    convertKeyToJca(y),
                    convertKeyToJca(p),
                    convertKeyToJca(g)
            );
            var serverPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPubKeySpecs);
            this.keyPair = TlsKeyPair.of(serverPublicKey);
        }catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot read DHE server key", exception);
        }
    }


    @Override
    public void serialize(ByteBuffer buffer) {
        var dhPublicKey = (DHPublicKey) keyPair.jcaPublicKey();
        var p = convertJcaToKey(dhPublicKey.getParams().getP());
        var g = convertJcaToKey(dhPublicKey.getParams().getP());
        var y = convertJcaToKey(dhPublicKey.getParams().getP());
        writeBytesLittleEndian16(buffer, p);
        writeBytesLittleEndian16(buffer, g);
        writeBytesLittleEndian16(buffer, y);
    }

    @Override
    public int length() {
        return INT16_LENGTH + COMPONENT_LENGTH
                + INT16_LENGTH + COMPONENT_LENGTH
                + INT16_LENGTH + COMPONENT_LENGTH;
    }

    @Override
    public byte[] generatePreMasterSecret(TlsKeyExchangeType.TlsClientKeyExchange clientKeyExchange) {
        if(!(clientKeyExchange instanceof DhClientKeyExchange dhClientKeyExchange)) {
            throw new TlsException("Key share mismatch");
        }

        switch (keyPair) {
            case TlsKeyPair.Local localKeyPair -> {
                switch (dhClientKeyExchange.tlsKeyPair()) {
                    case TlsKeyPair.Remote remote -> {
                        try {
                            var keyAgreement = KeyAgreement.getInstance("DH");
                            keyAgreement.init(localKeyPair.jceKeyPair().getPrivate());
                            keyAgreement.doPhase(remote.jcaPublicKey(), true);
                            return keyAgreement.generateSecret();
                        }catch (GeneralSecurityException exception) {
                            throw new TlsException("Cannot generate pre master secret", exception);
                        }
                    }
                    case TlsKeyPair.Local _ -> throw new TlsException("Key share mismatch");
                }
            }
            case TlsKeyPair.Remote remote -> {
                switch (dhClientKeyExchange.tlsKeyPair()) {
                    case TlsKeyPair.Local local -> {
                        try {
                            var keyAgreement = KeyAgreement.getInstance("DH");
                            keyAgreement.init(local.jceKeyPair().getPrivate());
                            keyAgreement.doPhase(remote.jcaPublicKey(), true);
                            return keyAgreement.generateSecret();
                        }catch (GeneralSecurityException exception) {
                            throw new TlsException("Cannot generate pre master secret", exception);
                        }
                    }
                    case TlsKeyPair.Remote _ -> throw new TlsException("Key share mismatch");
                }
            }
        }
    }

    private static BigInteger convertKeyToJca(byte[] arr) {
        var result = new byte[32];
        var padding = result.length - arr.length;
        for(var i = 0; i < arr.length; i++) {
            result[i + padding] = arr[arr.length - (i + 1)];
        }

        return new BigInteger(result);
    }

    private static byte[] convertJcaToKey(BigInteger bigInteger) {
        var arr = bigInteger.toByteArray();
        var result = new byte[32];
        var padding = result.length - arr.length;
        for(var i = 0; i < arr.length; i++) {
            result[i + padding] = arr[arr.length - (i + 1)];
        }

        return result;
    }
}
