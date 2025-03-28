package it.auties.leap.tls.extension.implementation.keyShare;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

record KeyShareEntry(int namedGroup, byte[] publicKey) {
    public void serialize(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, namedGroup);
        writeBytesBigEndian16(buffer, publicKey);
    }

    public int length() {
        return INT16_LENGTH + INT16_LENGTH + publicKey.length;
    }
}
