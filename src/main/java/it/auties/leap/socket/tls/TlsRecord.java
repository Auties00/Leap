package it.auties.leap.socket.tls;

public interface TlsRecord {
    int INT8_LENGTH = 1;
    int INT16_LENGTH = 2;
    int INT24_LENGTH = 3;

    int MAC_LENGTH = 48;
    int DATA_LENGTH = 16384;
    int PADDING_LENGTH = 256;
    int IV_LENGTH = 16;
    int FRAGMENT_LENGTH = 18432;
    int TLS_HEADER_LENGTH = 5;
    int HANDSHAKE_HEADER_LENGTH = 4;
    int PLAINTEXT_LENGTH = TLS_HEADER_LENGTH
            + IV_LENGTH
            + MAC_LENGTH
            + PADDING_LENGTH;
    int RECORD_LENGTH = TLS_HEADER_LENGTH
            + IV_LENGTH
            + DATA_LENGTH
            + PADDING_LENGTH
            + MAC_LENGTH;
    int LARGE_RECORD_LENGTH = RECORD_LENGTH + DATA_LENGTH;
}
