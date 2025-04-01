package it.auties.leap.tls.cipher.engine.implementation;

import it.auties.leap.tls.cipher.engine.TlsCipherEngine;
import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.readLittleEndianInt32;
import static it.auties.leap.tls.util.BufferUtils.writeLittleEndianInt32;

public class ChaCha20Engine extends TlsCipherEngine.Stream {
    private final static int STATE_SIZE = 16;
    private final static int[] TAU_SIGMA = {1634760805, 824206446, 2036477238, 1797285236, 1634760805, 857760878, 2036477234, 1797285236};
    private static final int ROUNDS = 20;

    private static final TlsCipherEngineFactory FACTORY = new TlsCipherEngineFactory() {
        @Override
        public TlsCipherEngine newCipherEngine(boolean forEncryption, byte[] key) {
            if (key == null || key.length != keyLength()) {
                throw new IllegalArgumentException("Invalid key length");
            }

            return new ChaCha20Engine(forEncryption, key);
        }

        @Override
        public int keyLength() {
            return 32;
        }

        @Override
        public int blockLength() {
            return 0;
        }
    };

    private final int[] engineState; // state
    private final int[] x;
    private final byte[] keyStream;
    private int index;

    private ChaCha20Engine(boolean forEncryption, byte[] key) {
        super(forEncryption);
        this.engineState = new int[STATE_SIZE];
        this.x = new int[STATE_SIZE];
        this.keyStream = new byte[STATE_SIZE * 4];
        packTauOrSigma(key.length, engineState);
        for (int i = 0; i < 8; i++) {
            engineState[4 + i] = readLittleEndianInt32(key, i * 4);
        }
    }

    public static TlsCipherEngineFactory factory() {
        return FACTORY;
    }

    @Override
    public void cipher(ByteBuffer input, ByteBuffer output) {
        var initialPosition = output.position();
        while (input.hasRemaining()) {
            output.put((byte) (keyStream[index] ^ input.get()));
            index = (index + 1) & 63;
            if (index == 0) {
                advanceCounter();
                generateKeyStream(keyStream);
            }
        }
        output.limit(output.position());
        output.position(initialPosition);
    }

    private void advanceCounter() {
        if (++engineState[12] == 0) {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }
    }

    private void packTauOrSigma(int keyLength, int[] state) {
        int tsOff = (keyLength - 16) / 4;
        state[0] = TAU_SIGMA[tsOff    ];
        state[1] = TAU_SIGMA[tsOff + 1];
        state[2] = TAU_SIGMA[tsOff + 2];
        state[3] = TAU_SIGMA[tsOff + 3];
    }

    private void resetCounter() {
        engineState[12] = 0;
    }

    private void generateKeyStream(byte[] output) {
        var x00 = engineState[0];
        var x01 = engineState[1];
        var x02 = engineState[2];
        var x03 = engineState[3];
        var x04 = engineState[4];
        var x05 = engineState[5];
        var x06 = engineState[6];
        var x07 = engineState[7];
        var x08 = engineState[8];
        var x09 = engineState[9];
        var x10 = engineState[10];
        var x11 = engineState[11];
        var x12 = engineState[12];
        var x13 = engineState[13];
        var x14 = engineState[14];
        var x15 = engineState[15];

        for (var i = ROUNDS; i > 0; i -= 2) {
            x00 += x04;
            x12 = Integer.rotateLeft(x12 ^ x00, 16);
            x08 += x12;
            x04 = Integer.rotateLeft(x04 ^ x08, 12);
            x00 += x04;
            x12 = Integer.rotateLeft(x12 ^ x00, 8);
            x08 += x12;
            x04 = Integer.rotateLeft(x04 ^ x08, 7);
            x01 += x05;
            x13 = Integer.rotateLeft(x13 ^ x01, 16);
            x09 += x13;
            x05 = Integer.rotateLeft(x05 ^ x09, 12);
            x01 += x05;
            x13 = Integer.rotateLeft(x13 ^ x01, 8);
            x09 += x13;
            x05 = Integer.rotateLeft(x05 ^ x09, 7);
            x02 += x06;
            x14 = Integer.rotateLeft(x14 ^ x02, 16);
            x10 += x14;
            x06 = Integer.rotateLeft(x06 ^ x10, 12);
            x02 += x06;
            x14 = Integer.rotateLeft(x14 ^ x02, 8);
            x10 += x14;
            x06 = Integer.rotateLeft(x06 ^ x10, 7);
            x03 += x07;
            x15 = Integer.rotateLeft(x15 ^ x03, 16);
            x11 += x15;
            x07 = Integer.rotateLeft(x07 ^ x11, 12);
            x03 += x07;
            x15 = Integer.rotateLeft(x15 ^ x03, 8);
            x11 += x15;
            x07 = Integer.rotateLeft(x07 ^ x11, 7);
            x00 += x05;
            x15 = Integer.rotateLeft(x15 ^ x00, 16);
            x10 += x15;
            x05 = Integer.rotateLeft(x05 ^ x10, 12);
            x00 += x05;
            x15 = Integer.rotateLeft(x15 ^ x00, 8);
            x10 += x15;
            x05 = Integer.rotateLeft(x05 ^ x10, 7);
            x01 += x06;
            x12 = Integer.rotateLeft(x12 ^ x01, 16);
            x11 += x12;
            x06 = Integer.rotateLeft(x06 ^ x11, 12);
            x01 += x06;
            x12 = Integer.rotateLeft(x12 ^ x01, 8);
            x11 += x12;
            x06 = Integer.rotateLeft(x06 ^ x11, 7);
            x02 += x07;
            x13 = Integer.rotateLeft(x13 ^ x02, 16);
            x08 += x13;
            x07 = Integer.rotateLeft(x07 ^ x08, 12);
            x02 += x07;
            x13 = Integer.rotateLeft(x13 ^ x02, 8);
            x08 += x13;
            x07 = Integer.rotateLeft(x07 ^ x08, 7);
            x03 += x04;
            x14 = Integer.rotateLeft(x14 ^ x03, 16);
            x09 += x14;
            x04 = Integer.rotateLeft(x04 ^ x09, 12);
            x03 += x04;
            x14 = Integer.rotateLeft(x14 ^ x03, 8);
            x09 += x14;
            x04 = Integer.rotateLeft(x04 ^ x09, 7);

        }

        x[0] = x00 + engineState[0];
        x[1] = x01 + engineState[1];
        x[2] = x02 + engineState[2];
        x[3] = x03 + engineState[3];
        x[4] = x04 + engineState[4];
        x[5] = x05 + engineState[5];
        x[6] = x06 + engineState[6];
        x[7] = x07 + engineState[7];
        x[8] = x08 + engineState[8];
        x[9] = x09 + engineState[9];
        x[10] = x10 + engineState[10];
        x[11] = x11 + engineState[11];
        x[12] = x12 + engineState[12];
        x[13] = x13 + engineState[13];
        x[14] = x14 + engineState[14];
        x[15] = x15 + engineState[15];

        for(var i = 0; i < x.length; i++) {
            writeLittleEndianInt32(x[i], output, i * 4);
        }
    }

    public void initIV(byte[] nonce) {
        for(var i = 0; i < 3; ++i) {
            engineState[13 + i] = readLittleEndianInt32(nonce, i * 4);
        }
        index = 0;
        resetCounter();
        generateKeyStream(keyStream);
    }
}
