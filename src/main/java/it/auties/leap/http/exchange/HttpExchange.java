package it.auties.leap.http.exchange;

import it.auties.leap.http.HttpVersion;

import java.nio.ByteBuffer;

public sealed interface HttpExchange {
    void serialize(HttpVersion version, ByteBuffer buffer);
    int length();
}
