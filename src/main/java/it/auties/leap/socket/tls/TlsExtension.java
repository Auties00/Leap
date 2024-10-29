package it.auties.leap.socket.tls;

import it.auties.leap.socket.tls.extension.*;

import java.security.SecureRandom;
import java.util.List;

public abstract class TlsExtension implements TlsRecord {
    public static TlsExtension extendedMasterSecret() {
        return ExtendedMasterSecretExtension.INSTANCE;
    }

    public static TlsExtension encryptThenMac() {
        return EncryptThenMacExtension.INSTANCE;
    }

    public static TlsExtension postHandshakeAuth() {
        return PostHandshakeAuthExtension.INSTANCE;
    }

    public static TlsExtension nextProtocolNegotiation() {
        return NextProtocolNegotiationExtension.INSTANCE;
    }

    public static TlsExtension grease0A(SecureRandom random) {
        return GreaseExtension.INSTANCES[0];
    }

    public static TlsExtension grease1A(SecureRandom random) {
        return GreaseExtension.INSTANCES[1];
    }

    public static TlsExtension grease2A(SecureRandom random) {
        return GreaseExtension.INSTANCES[2];
    }

    public static TlsExtension grease3A(SecureRandom random) {
        return GreaseExtension.INSTANCES[3];
    }

    public static TlsExtension grease4A(SecureRandom random) {
        return GreaseExtension.INSTANCES[4];
    }

    public static TlsExtension grease5A(SecureRandom random) {
        return GreaseExtension.INSTANCES[5];
    }

    public static TlsExtension grease6A(SecureRandom random) {
        return GreaseExtension.INSTANCES[6];
    }

    public static TlsExtension grease7A(SecureRandom random) {
        return GreaseExtension.INSTANCES[7];
    }

    public static TlsExtension grease8A(SecureRandom random) {
        return GreaseExtension.INSTANCES[8];
    }

    public static TlsExtension grease9A(SecureRandom random) {
        return GreaseExtension.INSTANCES[9];
    }

    public static TlsExtension greaseAA(SecureRandom random) {
        return GreaseExtension.INSTANCES[10];
    }

    public static TlsExtension greaseBA(SecureRandom random) {
        return GreaseExtension.INSTANCES[11];
    }

    public static TlsExtension greaseCA(SecureRandom random) {
        return GreaseExtension.INSTANCES[12];
    }

    public static TlsExtension greaseDA(SecureRandom random) {
        return GreaseExtension.INSTANCES[13];
    }

    public static TlsExtension greaseEA(SecureRandom random) {
        return GreaseExtension.INSTANCES[14];
    }

    public static TlsExtension greaseFA(SecureRandom random) {
        return GreaseExtension.INSTANCES[15];
    }

    public static TlsExtension greaseRandom() {
        return greaseRandom(new SecureRandom());
    }

    public static TlsExtension greaseRandom(SecureRandom random) {
        var instances = GreaseExtension.INSTANCES;
        return instances[random.nextInt(0, instances.length)];
    }

    public static List<TlsExtension> windows() {
        throw new UnsupportedOperationException();
    }

    public static List<TlsExtension> mac() {
        throw new UnsupportedOperationException();
    }

    public static List<TlsExtension> linux() {
        throw new UnsupportedOperationException();
    }

    public static List<TlsExtension> ios() {
        throw new UnsupportedOperationException();
    }

    public static List<TlsExtension> android() {
        throw new UnsupportedOperationException();
    }

    public int serializeExtension(byte[] out, int offset) {
        var extensionType = extensionType();
        out[offset++] = (byte) (extensionType >> 8);
        out[offset++] = (byte) (extensionType);
        var extensionLength = extensionPayloadLength();
        out[offset++] = (byte) (extensionLength >> 8);
        out[offset++] = (byte) (extensionLength);
        return serializeExtensionPayload(out, offset);
    }

    public int extensionLength() {
        return INT16_LENGTH + INT16_LENGTH + extensionPayloadLength();
    }

    protected abstract int serializeExtensionPayload(byte[] out, int offset);

    public abstract int extensionPayloadLength();

    public abstract int extensionType();
}
