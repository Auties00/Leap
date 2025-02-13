package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.*;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * An implementation of TLS’s AES‐CCM cipher mode.
 * <p>
 * In TLS, the nonce is built by concatenating the fixed IV (the “implicit nonce”)
 * with an explicit nonce (generated per–record). The AAD is built from the TLS record header.
 * <p>
 * This implementation “manually” computes the CBC–MAC and CTR portions of the CCM algorithm
 * (RFC 3610, RFC 6655). Note that a production implementation should use a thoroughly tested library.
 */
public final class CCMMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = CCMMode::new;
    /**
     * The total nonce length in bytes (typically 12 for AES–CCM).
     */
    private static final int NONCE_LENGTH = 12;
    /**
     * The length of the explicit (per–record) nonce. In TLS the fixed IV is provided in the key material.
     * For example, if NONCE_LENGTH is 12 and the fixed IV is 4 bytes then the explicit nonce is 8 bytes.
     */
    private static final int EXPLICIT_NONCE_LENGTH = 8;
    /**
     * The length of the authentication tag (in bytes). (AES–CCM allows 4, 6, 8, 10, 12, 14, or 16.)
     */
    private static final int TAG_LENGTH = 16;
    /**
     * The number of bytes used to encode the message length in the B₀ block.
     * (Typically 2 bytes in TLS.)
     */
    private static final int L = 2;

    private SecureRandom random;

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(TlsExchangeAuthenticator authenticator, TlsCipherEngine engine, byte[] fixedIv) {
        super.init(authenticator, engine, fixedIv);
        this.random = new SecureRandom();
        // In this design, we expect fixedIv.length == NONCE_LENGTH - EXPLICIT_NONCE_LENGTH.
        if (fixedIv.length != NONCE_LENGTH - EXPLICIT_NONCE_LENGTH) {
            throw new IllegalArgumentException("Invalid fixed IV length for CCM mode: expected " +
                    (NONCE_LENGTH - EXPLICIT_NONCE_LENGTH) + " bytes, got " + fixedIv.length);
        }
    }

    @Override
    public void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        if (engine().forEncryption()) {
            // === ENCRYPTION ===
            byte[] plaintext = new byte[input.remaining()];
            input.get(plaintext);

            // Generate an explicit nonce
            byte[] explicitNonce = new byte[EXPLICIT_NONCE_LENGTH];
            random.nextBytes(explicitNonce);

            // Build the complete nonce: fixedIv || explicitNonce.
            byte[] nonce = new byte[NONCE_LENGTH];
            System.arraycopy(fixedIv, 0, nonce, 0, fixedIv.length);
            System.arraycopy(explicitNonce, 0, nonce, fixedIv.length, EXPLICIT_NONCE_LENGTH);

            // Build AAD (13 bytes): 8–byte sequence || 1–byte contentType || 2–byte version || 2–byte length.
            // The “length” here is the length of the CCM output (encrypted plaintext + tag).
            int payloadLength = plaintext.length + TAG_LENGTH;
            byte[] aad = new byte[13];
            if (sequence.length != 8) {
                throw new IllegalArgumentException("Sequence must be 8 bytes");
            }
            System.arraycopy(sequence, 0, aad, 0, 8);
            aad[8] = contentType;
            var versionBytes = authenticator.version();
            aad[9] = versionBytes.id().major();
            aad[10] = versionBytes.id().minor();
            aad[11] = (byte) (payloadLength >>> 8);
            aad[12] = (byte) (payloadLength);

            // Compute CCM encryption: this produces (ciphertext || tag)
            byte[] ccmOutput = encryptCCM(nonce, aad, plaintext);

            // The TLS record will carry: explicitNonce || (ciphertext || tag)
            output.put(explicitNonce);
            output.put(ccmOutput);
        } else {
            // === DECRYPTION ===
            if (input.remaining() < EXPLICIT_NONCE_LENGTH) {
                throw new TlsException("Input too short for explicit nonce");
            }
            // Read the explicit nonce.
            byte[] explicitNonce = new byte[EXPLICIT_NONCE_LENGTH];
            input.get(explicitNonce);

            // Build the full nonce.
            byte[] nonce = new byte[NONCE_LENGTH];
            System.arraycopy(fixedIv, 0, nonce, 0, fixedIv.length);
            System.arraycopy(explicitNonce, 0, nonce, fixedIv.length, EXPLICIT_NONCE_LENGTH);

            // The remainder of the record is the CCM ciphertext and tag.
            byte[] ccmInput = new byte[input.remaining()];
            input.get(ccmInput);

            // Rebuild AAD exactly as in encryption.
            int payloadLength = ccmInput.length;
            byte[] aad = new byte[13];
            if (sequence.length != 8) {
                throw new IllegalArgumentException("Sequence must be 8 bytes");
            }
            System.arraycopy(sequence, 0, aad, 0, 8);
            aad[8] = contentType;
            var versionBytes = authenticator.version();
            aad[9] = versionBytes.id().major();
            aad[10] = versionBytes.id().minor();
            aad[11] = (byte) (payloadLength >>> 8);
            aad[12] = (byte) (payloadLength);

            byte[] plaintext = decryptCCM(nonce, aad, ccmInput);
            output.put(plaintext);
        }
    }

    @Override
    public void doFinal(byte contentType, ByteBuffer input, ByteBuffer output) {
        // No finalization step is needed.
    }

    @Override
    public void reset() {
        // CCM mode is stateless per record.
    }

    @Override
    public TlsCipherIV ivLength() {
        // The total nonce length is NONCE_LENGTH and the explicit nonce is EXPLICIT_NONCE_LENGTH.
        return new TlsCipherIV(NONCE_LENGTH, EXPLICIT_NONCE_LENGTH);
    }

    @Override
    public int tagLength() {
        return TAG_LENGTH;
    }

    /*
     * === CCM ENCRYPTION / DECRYPTION IMPLEMENTATION ===
     *
     * The following helper methods implement the CCM algorithm.
     * (See RFC 3610 and RFC 6655 for details.)
     */

    /**
     * Encrypts the given plaintext using CCM.
     *
     * @param nonce     the full nonce (fixed IV || explicit nonce)
     * @param aad       the additional authenticated data (13 bytes, from the TLS header)
     * @param plaintext the plaintext to encrypt
     * @return the concatenation of the ciphertext and the authentication tag.
     */
    private byte[] encryptCCM(byte[] nonce, byte[] aad, byte[] plaintext) {
        int blockSize = engine().blockLength();
        int tagLength = TAG_LENGTH;

        // === 1. Construct B₀ ===
        byte flags = 0;
        if (aad != null && aad.length > 0) {
            flags |= 0x40;
        }
        flags |= ((tagLength - 2) / 2) << 3;
        flags |= (L - 1);
        byte[] B0 = new byte[blockSize];
        B0[0] = flags;
        System.arraycopy(nonce, 0, B0, 1, nonce.length);
        int m = plaintext.length;
        for (int i = 0; i < L; i++) {
            B0[blockSize - 1 - i] = (byte) (m >>> (8 * i));
        }

        // === 2. Compute the CBC–MAC ===
        byte[] X = new byte[blockSize]; // starts at all zeros
        X = cipherBlockXorAndEncrypt(X, B0);

        // Process the AAD:
        if (aad != null && aad.length > 0) {
            // Encode the length of AAD in 2 bytes (since aad.length < 0xFF00 in TLS)
            if (aad.length >= 0xFF00) {
                throw new UnsupportedOperationException("AAD too long");
            }
            byte[] encodedAAD = new byte[2 + aad.length];
            encodedAAD[0] = (byte) (aad.length >>> 8);
            encodedAAD[1] = (byte) (aad.length);
            System.arraycopy(aad, 0, encodedAAD, 2, aad.length);
            // Pad encoded AAD to a multiple of blockSize
            int padLength = (blockSize - (encodedAAD.length % blockSize)) % blockSize;
            byte[] aadPadded = new byte[encodedAAD.length + padLength];
            System.arraycopy(encodedAAD, 0, aadPadded, 0, encodedAAD.length);
            for (int i = 0; i < aadPadded.length; i += blockSize) {
                byte[] block = new byte[blockSize];
                System.arraycopy(aadPadded, i, block, 0, blockSize);
                X = cipherBlockXorAndEncrypt(X, block);
            }
        }

        // Process the plaintext (if its length is not a multiple of blockSize, pad with zeros)
        int remainder = plaintext.length % blockSize;
        int paddedLength = plaintext.length;
        if (remainder != 0) {
            paddedLength = plaintext.length + (blockSize - remainder);
        }
        byte[] plaintextPadded = new byte[paddedLength];
        System.arraycopy(plaintext, 0, plaintextPadded, 0, plaintext.length);
        for (int i = 0; i < plaintextPadded.length; i += blockSize) {
            byte[] block = new byte[blockSize];
            System.arraycopy(plaintextPadded, i, block, 0, blockSize);
            X = cipherBlockXorAndEncrypt(X, block);
        }

        // === 3. Compute S₀ for tag calculation ===
        byte[] A0 = new byte[blockSize];
        A0[0] = (byte) (L - 1);
        System.arraycopy(nonce, 0, A0, 1, nonce.length);
        // The last L bytes are zero.
        byte[] S0 = encryptBlock(A0);
        byte[] tag = new byte[tagLength];
        for (int i = 0; i < tagLength; i++) {
            tag[i] = (byte) (X[i] ^ S0[i]);
        }

        // === 4. Encrypt the plaintext with CTR mode (counter starts at 1) ===
        int blocks = (plaintext.length + blockSize - 1) / blockSize;
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 1; i <= blocks; i++) {
            byte[] Ai = new byte[blockSize];
            Ai[0] = (byte) (L - 1);
            System.arraycopy(nonce, 0, Ai, 1, nonce.length);
            // Set the counter (i) in the last L bytes (big-endian)
            for (int j = 0; j < L; j++) {
                Ai[blockSize - 1 - j] = (byte) (i >>> (8 * j));
            }
            byte[] Si = encryptBlock(Ai);
            int offset = (i - 1) * blockSize;
            int blockLen = Math.min(blockSize, plaintext.length - offset);
            for (int j = 0; j < blockLen; j++) {
                ciphertext[offset + j] = (byte) (plaintext[offset + j] ^ Si[j]);
            }
        }

        // === 5. Return (ciphertext || tag) ===
        byte[] result = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
        System.arraycopy(tag, 0, result, ciphertext.length, tag.length);
        return result;
    }

    /**
     * Decrypts and authenticates a CCM ciphertext.
     *
     * @param nonce            the full nonce (fixedIv || explicit nonce)
     * @param aad              the additional authenticated data (from the TLS header)
     * @param ciphertextWithTag the ciphertext concatenated with the tag
     * @return the decrypted plaintext, if the tag is valid.
     * @throws TlsException if the authentication tag does not verify.
     */
    private byte[] decryptCCM(byte[] nonce, byte[] aad, byte[] ciphertextWithTag) throws TlsException {
        int blockSize = engine().blockLength();
        int tagLength = TAG_LENGTH;
        if (ciphertextWithTag.length < tagLength) {
            throw new TlsException("Ciphertext too short");
        }
        int ciphertextLength = ciphertextWithTag.length - tagLength;
        byte[] ciphertext = new byte[ciphertextLength];
        byte[] receivedTag = new byte[tagLength];
        System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLength);
        System.arraycopy(ciphertextWithTag, ciphertextLength, receivedTag, 0, tagLength);

        // === 1. Decrypt ciphertext with CTR mode (counter starts at 1) ===
        int blocks = (ciphertextLength + blockSize - 1) / blockSize;
        byte[] plaintext = new byte[ciphertextLength];
        for (int i = 1; i <= blocks; i++) {
            byte[] Ai = new byte[blockSize];
            Ai[0] = (byte) (L - 1);
            System.arraycopy(nonce, 0, Ai, 1, nonce.length);
            for (int j = 0; j < L; j++) {
                Ai[blockSize - 1 - j] = (byte) (i >>> (8 * j));
            }
            byte[] Si = encryptBlock(Ai);
            int offset = (i - 1) * blockSize;
            int blockLen = Math.min(blockSize, ciphertextLength - offset);
            for (int j = 0; j < blockLen; j++) {
                plaintext[offset + j] = (byte) (ciphertext[offset + j] ^ Si[j]);
            }
        }

        // === 2. Recompute the CBC–MAC over (B₀ || AAD || plaintext) ===
        byte flags = 0;
        if (aad != null && aad.length > 0) {
            flags |= 0x40;
        }
        flags |= ((tagLength - 2) / 2) << 3;
        flags |= (L - 1);
        byte[] B0 = new byte[blockSize];
        B0[0] = flags;
        System.arraycopy(nonce, 0, B0, 1, nonce.length);
        int m = plaintext.length;
        for (int i = 0; i < L; i++) {
            B0[blockSize - 1 - i] = (byte) (m >>> (8 * i));
        }
        byte[] X = new byte[blockSize];
        X = cipherBlockXorAndEncrypt(X, B0);

        // Process AAD (encoded with its length in 2 bytes)
        if (aad != null && aad.length > 0) {
            if (aad.length >= 0xFF00) {
                throw new UnsupportedOperationException("AAD too long");
            }
            byte[] encodedAAD = new byte[2 + aad.length];
            encodedAAD[0] = (byte) (aad.length >>> 8);
            encodedAAD[1] = (byte) (aad.length);
            System.arraycopy(aad, 0, encodedAAD, 2, aad.length);
            int padLength = (blockSize - (encodedAAD.length % blockSize)) % blockSize;
            byte[] aadPadded = new byte[encodedAAD.length + padLength];
            System.arraycopy(encodedAAD, 0, aadPadded, 0, encodedAAD.length);
            for (int i = 0; i < aadPadded.length; i += blockSize) {
                byte[] block = new byte[blockSize];
                System.arraycopy(aadPadded, i, block, 0, blockSize);
                X = cipherBlockXorAndEncrypt(X, block);
            }
        }

        // Process the plaintext blocks (pad final block with zeros if needed)
        int remainder = plaintext.length % blockSize;
        int paddedLength = plaintext.length;
        if (remainder != 0) {
            paddedLength = plaintext.length + (blockSize - remainder);
        }
        byte[] plaintextPadded = new byte[paddedLength];
        System.arraycopy(plaintext, 0, plaintextPadded, 0, plaintext.length);
        for (int i = 0; i < plaintextPadded.length; i += blockSize) {
            byte[] block = new byte[blockSize];
            System.arraycopy(plaintextPadded, i, block, 0, blockSize);
            X = cipherBlockXorAndEncrypt(X, block);
        }

        // === 3. Compute S₀ and the expected tag ===
        byte[] A0 = new byte[blockSize];
        A0[0] = (byte) (L - 1);
        System.arraycopy(nonce, 0, A0, 1, nonce.length);
        byte[] S0 = encryptBlock(A0);
        byte[] computedTag = new byte[tagLength];
        for (int i = 0; i < tagLength; i++) {
            computedTag[i] = (byte) (X[i] ^ S0[i]);
        }
        if (!Arrays.equals(computedTag, receivedTag)) {
            throw new TlsException("Invalid CCM authentication tag");
        }
        return plaintext;
    }

    /**
     * Encrypts a single block (of size engine().blockLength()) in ECB mode.
     *
     * @param block the block to encrypt.
     * @return the encrypted block.
     */
    private byte[] encryptBlock(byte[] block) {
        ByteBuffer inputBuffer = ByteBuffer.wrap(block);
        ByteBuffer outputBuffer = ByteBuffer.allocate(engine().blockLength());
        engine().update(inputBuffer, outputBuffer);
        return outputBuffer.array();
    }

    /**
     * XORs the given two blocks (assumed to be the same length) and encrypts the result.
     * Used to implement the CBC–MAC chaining.
     *
     * @param X     the current chaining value.
     * @param block the next block to process.
     * @return the new chaining value.
     */
    private byte[] cipherBlockXorAndEncrypt(byte[] X, byte[] block) {
        byte[] Y = new byte[X.length];
        for (int i = 0; i < X.length; i++) {
            Y[i] = (byte) (X[i] ^ block[i]);
        }
        return encryptBlock(Y);
    }
}
