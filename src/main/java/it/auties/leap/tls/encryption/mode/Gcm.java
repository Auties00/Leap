package it.auties.leap.tls.encryption.mode;

import it.auties.leap.tls.TlsCipher.Type;
import it.auties.leap.tls.TlsSpecificationException;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.encryption.TlsEncryption;
import it.auties.leap.tls.auth.TlsAuthenticator;
import it.auties.leap.tls.key.TlsSessionKeys;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.message.TlsMessage.ContentType;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class Gcm extends TlsEncryption {
    public Gcm(TlsVersion version, Type type, TlsAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsEngineMode mode) {
        super(version, type, authenticator, sessionKeys, mode);
    }

    @Override
    public void encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        switch (version) {
            case TLS10, DTLS10, TLS11 -> throw new TlsSpecificationException("AesGcm ciphers are not allowed before (D)TLSv1.2");
            case TLS12, DTLS12 -> tls12Encrypt(contentType, input, output);
            case TLS13, DTLS13 -> throw new UnsupportedOperationException();
        }
    }

    private void tls12Encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        var outputPosition = output.position();

        var key = switch (mode) {
            case CLIENT -> sessionKeys.localCipherKey();
            case SERVER -> sessionKeys.remoteCipherKey();
        };

        var nonce = authenticator.sequenceNumber();

        var fixedIv = switch (mode) {
            case CLIENT -> sessionKeys.localIv();
            case SERVER -> sessionKeys.remoteIv();
        };
        var iv = Arrays.copyOf(fixedIv, fixedIv.length + nonce.length);
        System.arraycopy(nonce, 0, iv, fixedIv.length, nonce.length);

        var aad = authenticator.createAuthenticationBlock(
                contentType.id(),
                input.remaining(),
                null
        );

        var outputPositionWithNonce = outputPosition - nonce.length;
        output.position(outputPositionWithNonce);
        output.put(nonce);

        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    key,
                    new GCMParameterSpec(128, iv)
            );
            cipher.updateAAD(aad);
            cipher.doFinal(input, output);
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot encrypt message", exception);
        }

        output.limit(output.position())
                .position(outputPositionWithNonce);
    }


    @Override
    public void decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        switch (version) {
            case TLS10, DTLS10, TLS11 -> throw new TlsSpecificationException("AEAD ciphers are not allowed in (D)TLSv1.3");
            case TLS12, DTLS12 -> tls12Decrypt(contentType, input, output);
            case TLS13, DTLS13 -> throw new UnsupportedOperationException();
        }
    }

    private void tls12Decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        var outputPosition = output.position();

        var key = switch (mode) {
            case CLIENT -> sessionKeys.remoteCipherKey();
            case SERVER -> sessionKeys.localCipherKey();
        };

        var fixedIv = switch (mode) {
            case CLIENT -> sessionKeys.remoteIv();
            case SERVER -> sessionKeys.localIv();
        };

        var recordIvSize = type.ivLength() - type.fixedIvLength();
        var iv = Arrays.copyOf(fixedIv, fixedIv.length + recordIvSize);
        input.get(iv, fixedIv.length, recordIvSize);

        var aad = authenticator.createAuthenticationBlock(
                contentType.id(),
                input.remaining() - type.tagLength(),
                null
        );

        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    new GCMParameterSpec(128, iv)
            );
            cipher.updateAAD(aad);
            cipher.doFinal(input, output);
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot encrypt message", exception);
        }

        output.limit(output.position())
                .position(outputPosition);
    }

    @Override
    public int nonceLength() {
        return type.ivLength() - type.fixedIvLength();
    }
}
