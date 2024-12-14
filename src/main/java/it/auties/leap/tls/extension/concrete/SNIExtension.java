package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

import static it.auties.leap.tls.TlsBuffer.*;

public final class SNIExtension extends TlsConcreteExtension {
    public static final int EXTENSION_TYPE = 0x0000;

    private final byte[] name;
    private final NameType nameType;
    public SNIExtension(byte[] name, NameType nameType) {
        this.name = name;
        this.nameType = nameType;
    }

    public static Optional<SNIExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var listLength = readLittleEndianInt16(buffer);
        if(listLength == 0) {
            return Optional.empty();
        }

        try(var _ = scopedRead(buffer, listLength)) {
            var nameTypeId = readLittleEndianInt8(buffer);
            var nameType = NameType.of(nameTypeId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown name type: " + nameTypeId));
            var nameBytes = readBytesLittleEndian16(buffer);
            var extension = new SNIExtension(nameBytes, nameType);
            return Optional.of(extension);
        }
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        var listLength = INT8_LENGTH + INT16_LENGTH + name.length;
        writeLittleEndianInt16(buffer, listLength);

        writeLittleEndianInt8(buffer, nameType.id());

        writeBytesLittleEndian16(buffer, name);
    }

    @Override
    public int extensionPayloadLength() {
        return INT16_LENGTH + INT8_LENGTH + INT16_LENGTH + name.length;
    }

    @Override
    public int extensionType() {
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13);
    }

    public enum NameType {
        HOST_NAME((byte) 0, Checker::isHostName);

        private static final Map<Byte, NameType> VALUES = Map.of(
                HOST_NAME.id(), HOST_NAME
        );
        public static Optional<NameType> of(byte id) {
            return Optional.ofNullable(VALUES.get(id));
        }

        private final byte id;
        private final Predicate<String> checker;
        NameType(byte id, Predicate<String> checker) {
            this.id = id;
            this.checker = checker;
        }

        public byte id() {
            return id;
        }

        public boolean isValid(String value) {
            return checker.test(value);
        }
    }

    private static final class Checker {
        private static final int INADDR4SZ = 4;
        private static final int INADDR16SZ = 16;
        private static final int INT16SZ = 2;
        private static final int HEXADECIMAL = 16;
        private static final int DECIMAL = 10;
        private static final int OCTAL = 8;

        public static boolean isHostName(String serverName) {
            return serverName != null
                    && textToNumericFormatV4(serverName) == null
                    && textToNumericFormatV6(serverName) == null;
        }

        // Taken from sun.net.util.IPAddressUtil
        private static byte[] textToNumericFormatV6(String src) {
            if (src.length() < 2) {
                return null;
            }

            int colonp;
            char ch;
            boolean saw_xdigit;
            int val;
            char[] srcb = src.toCharArray();
            byte[] dst = new byte[INADDR16SZ];

            int srcb_length = srcb.length;
            int pc = src.indexOf('%');
            if (pc == srcb_length - 1) {
                return null;
            }

            if (pc != -1) {
                srcb_length = pc;
            }

            colonp = -1;
            int i = 0, j = 0;
            if (srcb[i] == ':') if (srcb[++i] != ':') return null;
            int curtok = i;
            saw_xdigit = false;
            val = 0;
            while (i < srcb_length) {
                ch = srcb[i++];
                int chval = parseAsciiDigit(ch, 16);
                if (chval != -1) {
                    val <<= 4;
                    val |= chval;
                    if (val > 0xffff) return null;
                    saw_xdigit = true;
                    continue;
                }
                if (ch == ':') {
                    curtok = i;
                    if (!saw_xdigit) {
                        if (colonp != -1) return null;
                        colonp = j;
                        continue;
                    } else if (i == srcb_length) {
                        return null;
                    }
                    if (j + INT16SZ > INADDR16SZ) return null;
                    dst[j++] = (byte) ((val >> 8) & 0xff);
                    dst[j++] = (byte) (val & 0xff);
                    saw_xdigit = false;
                    val = 0;
                    continue;
                }
                if (ch == '.' && ((j + INADDR4SZ) <= INADDR16SZ)) {
                    String ia4 = src.substring(curtok, srcb_length);
                    int dot_count = 0, index = 0;
                    while ((index = ia4.indexOf('.', index)) != -1) {
                        dot_count++;
                        index++;
                    }
                    if (dot_count != 3) {
                        return null;
                    }
                    byte[] v4addr = textToNumericFormatV4(ia4);
                    if (v4addr == null) {
                        return null;
                    }
                    for (int k = 0; k < INADDR4SZ; k++) {
                        dst[j++] = v4addr[k];
                    }
                    saw_xdigit = false;
                    break;
                }
                return null;
            }
            if (saw_xdigit) {
                if (j + INT16SZ > INADDR16SZ) return null;
                dst[j++] = (byte) ((val >> 8) & 0xff);
                dst[j++] = (byte) (val & 0xff);
            }

            if (colonp != -1) {
                int n = j - colonp;

                if (j == INADDR16SZ) return null;
                for (i = 1; i <= n; i++) {
                    dst[INADDR16SZ - i] = dst[colonp + n - i];
                    dst[colonp + n - i] = 0;
                }
                j = INADDR16SZ;
            }
            if (j != INADDR16SZ) return null;
            byte[] newdst = convertFromIPv4MappedAddress(dst);
            return Objects.requireNonNullElse(newdst, dst);
        }

        private static byte[] textToNumericFormatV4(String src) {
            byte[] res = new byte[INADDR4SZ];

            long tmpValue = 0;
            int currByte = 0;
            boolean newOctet = true;

            int len = src.length();
            if (len == 0 || len > 15) {
                return null;
            }

            for (int i = 0; i < len; i++) {
                char c = src.charAt(i);
                if (c == '.') {
                    if (newOctet || tmpValue < 0 || tmpValue > 0xff || currByte == 3) {
                        return null;
                    }
                    res[currByte++] = (byte) (tmpValue & 0xff);
                    tmpValue = 0;
                    newOctet = true;
                } else {
                    int digit = parseAsciiDigit(c, 10);
                    if (digit < 0) {
                        return null;
                    }
                    tmpValue *= 10;
                    tmpValue += digit;
                    newOctet = false;
                }
            }
            if (newOctet || tmpValue < 0 || tmpValue >= (1L << ((4 - currByte) * 8))) {
                return null;
            }
            switch (currByte) {
                case 0:
                    res[0] = (byte) ((tmpValue >> 24) & 0xff);
                case 1:
                    res[1] = (byte) ((tmpValue >> 16) & 0xff);
                case 2:
                    res[2] = (byte) ((tmpValue >> 8) & 0xff);
                case 3:
                    res[3] = (byte) ((tmpValue) & 0xff);
            }
            return res;
        }

        private static byte[] convertFromIPv4MappedAddress(byte[] addr) {
            if (!isIPv4MappedAddress(addr)) {
                return null;
            }

            byte[] newAddr = new byte[INADDR4SZ];
            System.arraycopy(addr, 12, newAddr, 0, INADDR4SZ);
            return newAddr;
        }

        private static int parseAsciiDigit(char c, int radix) {
            assert radix == OCTAL || radix == DECIMAL || radix == HEXADECIMAL;
            if (radix == HEXADECIMAL) {
                return parseAsciiHexDigit(c);
            }
            int val = c - '0';
            return (val < 0 || val >= radix) ? -1 : val;
        }

        private static int parseAsciiHexDigit(char digit) {
            char c = Character.toLowerCase(digit);
            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }
            return parseAsciiDigit(c, DECIMAL);
        }

        private static boolean isIPv4MappedAddress(byte[] addr) {
            return addr.length >= INADDR16SZ && (addr[0] == 0x00)
                    && (addr[1] == 0x00) && (addr[2] == 0x00)
                    && (addr[3] == 0x00) && (addr[4] == 0x00)
                    && (addr[5] == 0x00) && (addr[6] == 0x00)
                    && (addr[7] == 0x00) && (addr[8] == 0x00)
                    && (addr[9] == 0x00)
                    && (addr[10] == (byte) 0xff)
                    && (addr[11] == (byte) 0xff);
        }
    }
}
