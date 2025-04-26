package it.auties.leap.codegen;

import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;
import java.util.HexFormat;

public class EmptyTest {
    public static void main(String[] args) {
        var metadata = TlsMessageMetadata.of(ByteBuffer.wrap(HexFormat.of().parseHex("14000030b8a381c7ba9cc6cd3de9915c30f599e8d072703e4cb65c469f6339ec7ff3f90185271601d4c007d0540cbf04be3b9c8d")), TlsSource.REMOTE);
        System.out.println(metadata);
    }
}
