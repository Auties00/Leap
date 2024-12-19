package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.message.TlsMessage;

import java.nio.ByteBuffer;

public class NoneMode extends TlsCipherMode.Block {
    @Override
    public void update(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        addMac(input, contentType.id());
        move(input, output);
    }

    @Override
    public void doFinal(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {
        addMac(input, contentType.id());
        move(input, output);
    }

    @Override
    public void reset() {

    }

    @Override
    public int nonceLength() {
        return 0;
    }

    private void move(ByteBuffer input, ByteBuffer output) {
        var outputPosition = output.position();
        output.put(input)
                .limit(output.position())
                .position(outputPosition);
    }
}
