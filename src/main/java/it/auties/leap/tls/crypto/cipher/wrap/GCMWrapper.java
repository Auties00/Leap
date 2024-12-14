package it.auties.leap.tls.crypto.cipher.wrap;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsSpecificationException;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.crypto.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.crypto.key.TlsSessionKeys;
import it.auties.leap.tls.message.TlsMessage.ContentType;

import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.crypto.cipher.TlsCipherEngine.Mode.*;

final class GCMWrapper extends TlsCipherWrapper {
    GCMWrapper(TlsVersion version, TlsCipher cipher, TlsExchangeAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsEngineMode mode) {
        super(version, cipher, authenticator, sessionKeys, mode);
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

        var nonce = authenticator.sequenceNumber();

        var fixedIv = switch (mode) {
            case CLIENT -> sessionKeys.localIv();
            case SERVER -> sessionKeys.remoteIv();
        };
        var iv = Arrays.copyOf(fixedIv, fixedIv.length + nonce.length);
        System.arraycopy(nonce, 0, iv, fixedIv.length, nonce.length);
        var ivSpec = new GCMParameterSpec(128, iv);

        var aad = authenticator.createAuthenticationBlock(
                contentType.id(),
                input.remaining(),
                null
        );

        var outputPositionWithNonce = outputPosition - nonce.length;
        output.position(outputPositionWithNonce);
        output.put(nonce);

        var family = TlsCipherEngine.of(cipher, WRITE, ivSpec, sessionKeys, aad);
        family.wrap(input, output, true);

        output.limit(output.position());
        output.position(outputPositionWithNonce);
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

        var fixedIv = switch (mode) {
            case CLIENT -> sessionKeys.remoteIv();
            case SERVER -> sessionKeys.localIv();
        };

        var recordIvSize = cipher.type().ivLength() - cipher.type().fixedIvLength();
        var iv = Arrays.copyOf(fixedIv, fixedIv.length + recordIvSize);
        input.get(iv, fixedIv.length, recordIvSize);
        var ivSpec = new GCMParameterSpec(128, iv);
        var aad = authenticator.createAuthenticationBlock(
                contentType.id(),
                input.remaining() - cipher.type().tagLength(),
                null
        );

        var family = TlsCipherEngine.of(cipher, READ, ivSpec, sessionKeys, aad);
        family.unwrap(input, output, true);

        output.limit(output.position());
        output.position(outputPosition);
    }

    @Override
    public int nonceLength() {
        return cipher.type().ivLength() - cipher.type().fixedIvLength();
    }
}
