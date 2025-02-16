package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.*;
import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * An example implementation of TLS’s AES–GCM cipher mode.
 * <p>
 * In TLS, the 12–byte nonce is constructed by concatenating a fixed IV (the “implicit nonce”)
 * with an explicit (per–record) IV. The AAD is built from the TLS record header.
 * <p>
 * This implementation “manually” combines CTR encryption with a GHASH computation.
 * For a production system, please consider using a well–vetted library.
 */
public final class GCMMode extends TlsCipherMode.Block {
    private static final TlsCipherModeFactory FACTORY = GCMMode::new;
    /**
     * Total nonce length in bytes (recommended 12 for AES–GCM).
     */
    private static final int NONCE_LENGTH = 12;
    /**
     * Length of the explicit (per–record) nonce.
     * For example, if NONCE_LENGTH is 12 and fixed IV is 4 bytes, then EXPLICIT_NONCE_LENGTH is 8.
     */
    private static final int EXPLICIT_NONCE_LENGTH = 8;
    /**
     * Authentication tag length in bytes.
     */
    private static final int TAG_LENGTH = 16;

    private SecureRandom random;
    /**
     * The GCM hash subkey H, computed as E_K(0^128).
     */
    private byte[] H;

    public GCMMode(TlsCipherEngine engine) {
        super(engine);
    }

    public static TlsCipherModeFactory factory() {
        return FACTORY;
    }

    @Override
    public void init(TlsExchangeAuthenticator authenticator, byte[] fixedIv) {
        super.init(authenticator, fixedIv);
        this.random = new SecureRandom();
        // In TLS AES-GCM the fixed IV must be NONCE_LENGTH - EXPLICIT_NONCE_LENGTH bytes.
        if (fixedIv.length != NONCE_LENGTH - EXPLICIT_NONCE_LENGTH) {
            throw new IllegalArgumentException("Invalid fixed IV length for GCM mode: expected " +
                    (NONCE_LENGTH - EXPLICIT_NONCE_LENGTH) + " bytes, got " + fixedIv.length);
        }
        // Compute the hash subkey H = E_K(0^128)
        byte[] zeroBlock = new byte[engine().blockLength()];
        this.H = encryptBlock(zeroBlock);
    }

    @Override
    public void update(byte contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        if (engine().forEncryption()) {
            // === ENCRYPTION PATH ===
            byte[] plaintext = new byte[input.remaining()];
            input.get(plaintext);

            // Generate an explicit nonce (per–record)
            byte[] explicitNonce = new byte[EXPLICIT_NONCE_LENGTH];
            random.nextBytes(explicitNonce);

            // Build the full nonce: fixed IV || explicit nonce
            byte[] nonce = new byte[NONCE_LENGTH];
            System.arraycopy(fixedIv, 0, nonce, 0, fixedIv.length);
            System.arraycopy(explicitNonce, 0, nonce, fixedIv.length, EXPLICIT_NONCE_LENGTH);

            // Build AAD (13 bytes: 8–byte sequence || 1–byte contentType || 2–byte version || 2–byte length)
            // The length field is the length of (ciphertext || tag)
            int payloadLength = plaintext.length + TAG_LENGTH;
            byte[] aad = new byte[13];
            if(sequence != null) {
                if (sequence.length != 8) {
                    throw new IllegalArgumentException("Sequence must be 8 bytes");
                }
                System.arraycopy(sequence, 0, aad, 0, 8);
            }
            aad[8] = contentType;
            var versionBytes = authenticator.version();
            aad[9] = versionBytes.id().major();
            aad[10] = versionBytes.id().minor();
            aad[11] = (byte) (payloadLength >>> 8);
            aad[12] = (byte) (payloadLength);

            // Compute J0. For a 12–byte nonce, J0 = (nonce || 0x00000001)
            byte[] J0 = new byte[16];
            System.arraycopy(nonce, 0, J0, 0, NONCE_LENGTH);
            J0[15] = 0x01;

            // Encrypt plaintext using CTR mode with counter starting at inc(J0)
            byte[] counter = Arrays.copyOf(J0, 16);
            incrementCounter(counter);
            int blockSize = engine().blockLength(); // should be 16 bytes
            byte[] ciphertext = new byte[plaintext.length];
            int blocks = (plaintext.length + blockSize - 1) / blockSize;
            for (int i = 0; i < blocks; i++) {
                byte[] keystream = encryptBlock(counter);
                int offset = i * blockSize;
                int len = Math.min(blockSize, plaintext.length - offset);
                for (int j = 0; j < len; j++) {
                    ciphertext[offset + j] = (byte) (plaintext[offset + j] ^ keystream[j]);
                }
                incrementCounter(counter);
            }

            // Compute GHASH over AAD and ciphertext
            byte[] S = ghash(H, aad, ciphertext);

            // Compute authentication tag: tag = E_K(J0) XOR S
            byte[] E_J0 = encryptBlock(J0);
            byte[] tag = new byte[TAG_LENGTH];
            for (int i = 0; i < TAG_LENGTH; i++) {
                tag[i] = (byte) (E_J0[i] ^ S[i]);
            }

            // Output the TLS record: explicit nonce || ciphertext || tag
            output.put(explicitNonce);
            output.put(ciphertext);
            output.put(tag);
        } else {
            // === DECRYPTION PATH ===
            if (input.remaining() < EXPLICIT_NONCE_LENGTH + TAG_LENGTH) {
                throw new TlsException("Input too short for explicit nonce and tag");
            }
            // Read the explicit nonce.
            byte[] explicitNonce = new byte[EXPLICIT_NONCE_LENGTH];
            input.get(explicitNonce);

            // Rebuild the full nonce.
            byte[] nonce = new byte[NONCE_LENGTH];
            System.arraycopy(fixedIv, 0, nonce, 0, fixedIv.length);
            System.arraycopy(explicitNonce, 0, nonce, fixedIv.length, EXPLICIT_NONCE_LENGTH);

            // The remaining input is: ciphertext || tag
            int remaining = input.remaining();
            if (remaining < TAG_LENGTH) {
                throw new TlsException("Input too short: missing tag");
            }
            int ciphertextLength = remaining - TAG_LENGTH;
            byte[] ciphertext = new byte[ciphertextLength];
            input.get(ciphertext);
            byte[] receivedTag = new byte[TAG_LENGTH];
            input.get(receivedTag);

            // Rebuild the AAD exactly as in encryption.
            int payloadLength = ciphertextLength + TAG_LENGTH;
            byte[] aad = new byte[13];
            if(sequence != null) {
                if (sequence.length != 8) {
                    throw new IllegalArgumentException("Sequence must be 8 bytes");
                }
                System.arraycopy(sequence, 0, aad, 0, 8);
            }
            aad[8] = contentType;
            var versionBytes = authenticator.version();
            aad[9] = versionBytes.id().major();
            aad[10] = versionBytes.id().minor();
            aad[11] = (byte) (payloadLength >>> 8);
            aad[12] = (byte) (payloadLength);

            // Compute J0.
            byte[] J0 = new byte[16];
            System.arraycopy(nonce, 0, J0, 0, NONCE_LENGTH);
            J0[15] = 0x01;

            // Compute the expected tag.
            byte[] S = ghash(H, aad, ciphertext);
            byte[] E_J0 = encryptBlock(J0);
            byte[] expectedTag = new byte[TAG_LENGTH];
            for (int i = 0; i < TAG_LENGTH; i++) {
                expectedTag[i] = (byte) (E_J0[i] ^ S[i]);
            }
            if (!Arrays.equals(expectedTag, receivedTag)) {
                throw new TlsException("Invalid GCM authentication tag");
            }

            // Decrypt ciphertext using CTR mode.
            byte[] counter = Arrays.copyOf(J0, 16);
            incrementCounter(counter);
            int blockSize = engine().blockLength();
            byte[] plaintext = new byte[ciphertextLength];
            int blocks = (ciphertextLength + blockSize - 1) / blockSize;
            for (int i = 0; i < blocks; i++) {
                byte[] keystream = encryptBlock(counter);
                int offset = i * blockSize;
                int len = Math.min(blockSize, ciphertextLength - offset);
                for (int j = 0; j < len; j++) {
                    plaintext[offset + j] = (byte) (ciphertext[offset + j] ^ keystream[j]);
                }
                incrementCounter(counter);
            }
            output.put(plaintext);
        }
    }

    @Override
    public void reset() {
        // GCM mode is stateless per record.
    }

    @Override
    public TlsCipherIV ivLength() {
        // Total nonce length is NONCE_LENGTH; explicit nonce length is EXPLICIT_NONCE_LENGTH.
        return new TlsCipherIV(NONCE_LENGTH - EXPLICIT_NONCE_LENGTH, EXPLICIT_NONCE_LENGTH);
    }

    @Override
    public int tagLength() {
        return TAG_LENGTH;
    }

    /*
     * === Helper Methods ===
     */

    /**
     * Encrypts a single block (of engine().blockLength() bytes) using the underlying block cipher in ECB mode.
     *
     * @param block the input block.
     * @return the encrypted block.
     */
    private byte[] encryptBlock(byte[] block) {
        ByteBuffer inputBuffer = ByteBuffer.wrap(block);
        ByteBuffer outputBuffer = ByteBuffer.allocate(engine().blockLength());
        engine().update(inputBuffer, outputBuffer);
        return outputBuffer.array();
    }

    /**
     * Increments the counter portion (the last 4 bytes) of the 16-byte counter block.
     *
     * @param counter the counter block.
     */
    private void incrementCounter(byte[] counter) {
        // The counter is in the last 4 bytes (big-endian).
        for (int i = counter.length - 1; i >= counter.length - 4; i--) {
            counter[i]++;
            if (counter[i] != 0) {
                break;
            }
        }
    }

    /**
     * Computes the GHASH function over the given AAD and ciphertext using the hash subkey H.
     * <p>
     * GHASH is defined over GF(2^128) with the polynomial
     * x^128 + x^7 + x^2 + x + 1.
     *
     * @param H          the hash subkey.
     * @param aad        the additional authenticated data.
     * @param ciphertext the ciphertext.
     * @return the 16–byte GHASH result.
     */
    private byte[] ghash(byte[] H, byte[] aad, byte[] ciphertext) {
        int blockSize = 16;
        byte[] X = new byte[blockSize]; // initialize to 0

        // Process AAD in 16-byte blocks.
        X = processBlocks(X, aad);
        // Process ciphertext in 16-byte blocks.
        X = processBlocks(X, ciphertext);

        // Process the length block: 64-bit lengths (in bits) for AAD and ciphertext.
        byte[] lengthBlock = new byte[blockSize];
        long aadBits = ((long) aad.length) * 8;
        long ciphertextBits = ((long) ciphertext.length) * 8;
        for (int i = 0; i < 8; i++) {
            lengthBlock[i] = (byte) (aadBits >>> (56 - 8 * i));
        }
        for (int i = 0; i < 8; i++) {
            lengthBlock[8 + i] = (byte) (ciphertextBits >>> (56 - 8 * i));
        }
        X = multiplyGF(xorBlock(X, lengthBlock), H);
        return X;
    }

    /**
     * Processes the given data in 16–byte blocks, updating the GHASH value.
     *
     * @param X    the current GHASH accumulator.
     * @param data the data to process.
     * @return the updated GHASH accumulator.
     */
    private byte[] processBlocks(byte[] X, byte[] data) {
        int blockSize = 16;
        int fullBlocks = data.length / blockSize;
        int remainder = data.length % blockSize;
        for (int i = 0; i < fullBlocks; i++) {
            byte[] block = Arrays.copyOfRange(data, i * blockSize, (i + 1) * blockSize);
            X = multiplyGF(xorBlock(X, block), H);
        }
        if (remainder > 0) {
            byte[] block = new byte[blockSize];
            System.arraycopy(data, fullBlocks * blockSize, block, 0, remainder);
            X = multiplyGF(xorBlock(X, block), H);
        }
        return X;
    }

    /**
     * Multiplies two 128–bit blocks in GF(2^128) defined by the polynomial
     * x^128 + x^7 + x^2 + x + 1.
     *
     * @param X the first 16–byte block.
     * @param Y the second 16–byte block.
     * @return the 16–byte product.
     */
    private byte[] multiplyGF(byte[] X, byte[] Y) {
        byte[] Z = new byte[16];
        byte[] V = Arrays.copyOf(Y, 16);
        for (int i = 0; i < 128; i++) {
            int bit = (X[i / 8] >> (7 - (i % 8))) & 1;
            if (bit == 1) {
                Z = xorBlock(Z, V);
            }
            boolean msbSet = (V[0] & 0x80) != 0;
            V = shiftLeft(V);
            if (msbSet) {
                // Reduction: XOR with 0x87 in the least significant byte.
                V[15] ^= 0x87;
            }
        }
        return Z;
    }

    /**
     * XORs two byte arrays of equal length.
     *
     * @param a the first byte array.
     * @param b the second byte array.
     * @return the XOR result.
     */
    private byte[] xorBlock(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /**
     * Shifts the given 16–byte block left by 1 bit.
     *
     * @param block the block to shift.
     * @return the shifted block.
     */
    private byte[] shiftLeft(byte[] block) {
        byte[] shifted = new byte[block.length];
        int carry = 0;
        for (int i = block.length - 1; i >= 0; i--) {
            int b = block[i] & 0xFF;
            shifted[i] = (byte) ((b << 1) | carry);
            carry = (b & 0x80) != 0 ? 1 : 0;
        }
        return shifted;
    }

    @Override
    public boolean isAEAD() {
        return true;
    }
}
