package it.auties.leap;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

@SuppressWarnings("unused")
public record HttpResponse<T>(int statusCode, T body) {
    public static abstract class Converter<T> {
        public static Converter<String> ofString(Charset charset) {
            return new Converter.Text(charset);
        }

        public static Converter<String> ofString() {
            return new Converter.Text(StandardCharsets.UTF_8);
        }

        public static Converter<ByteBuffer> ofBuffer() {
            return new Converter.Buffer();
        }

        public static Converter<byte[]> ofBytes() {
            return new Converter.Bytes();
        }

        public abstract HttpResponse<T> of(int statusCode, byte[] response);
        public abstract HttpResponse<T> empty(int statusCode);

        private static final class Text extends Converter<String> {
            private final Charset charset;
            private Text(Charset charset) {
                this.charset = charset;
            }

            @Override
            public HttpResponse<String> of(int statusCode, byte[] response) {
                var body = new String(response, charset);
                return new HttpResponse<>(statusCode, body);
            }

            @Override
            public HttpResponse<String> empty(int statusCode) {
                return new HttpResponse<>(statusCode, "");
            }
        }

        private static final class Bytes extends Converter<byte[]> {
            private static final byte[] EMPTY_BYTES = new byte[0];

            @Override
            public HttpResponse<byte[]> of(int statusCode, byte[] response) {
                return new HttpResponse<>(statusCode, response);
            }

            @Override
            public HttpResponse<byte[]> empty(int statusCode) {
                return new HttpResponse<>(statusCode, EMPTY_BYTES);
            }
        }

        private static final class Buffer extends Converter<ByteBuffer> {
            private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0).asReadOnlyBuffer();

            @Override
            public HttpResponse<ByteBuffer> of(int statusCode, byte[] response) {
                return new HttpResponse<>(statusCode, ByteBuffer.wrap(response));
            }

            @Override
            public HttpResponse<ByteBuffer> empty(int statusCode) {
                return new HttpResponse<>(statusCode, EMPTY_BUFFER);
            }
        }
    }
}
