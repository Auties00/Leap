package it.auties.leap.socket;

public sealed abstract class SocketOption<VALUE> {
    public static SocketOption<Integer> readBufferSize() {
        return ReadBufferSize.OPTION;
    }

    public static SocketOption<Integer> writeBufferSize() {
        return WriteBufferSize.OPTION;
    }

    public static SocketOption<Boolean> keepAlive() {
        return KeepAlive.OPTION;
    }

    private final String name;
    private final VALUE defaultValue;
    private SocketOption(String name, VALUE defaultValue) {
        this.defaultValue = defaultValue;
        this.name = name;
    }

    public abstract long accept(VALUE value);

    public String name() {
        return name;
    }

    public VALUE defaultValue() {
        return defaultValue;
    }

    public static final class ReadBufferSize extends SocketOption<Integer> {
        private static final ReadBufferSize OPTION = new ReadBufferSize();
        
        private ReadBufferSize() {
            super("READ_BUFFER", 8192);
        }

        @Override
        public long accept(Integer integer) {
            return integer == null ? 0 : integer;
        }
    }

    public static final class WriteBufferSize extends SocketOption<Integer> {
        private static final WriteBufferSize OPTION = new WriteBufferSize();
        
        private WriteBufferSize() {
            super("WRITE_BUFFER", 8192);
        }

        @Override
        public long accept(Integer integer) {
            return integer == null ? 0 : integer;
        }
    }

    public static final class KeepAlive extends SocketOption<Boolean> {
        private static final KeepAlive OPTION = new KeepAlive();
        
        private KeepAlive() {
            super("KEEP_ALIVE", false);
        }

        @Override
        public long accept(Boolean bool) {
            return bool != null && bool ? 1 : 0;
        }
    }
}
