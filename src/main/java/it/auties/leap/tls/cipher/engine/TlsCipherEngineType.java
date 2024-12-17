package it.auties.leap.tls.cipher.engine;

//     public enum Type {
//        NULL(0, 0, 0, 0, null, TlsCipherMode.none(), Category.NULL, TlsCipherEngine.none()),
//
//        AES_128_CBC(16, 0, 16, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.aes()),
//        AES_128_CCM(16, 0, 12, 4, null, TlsCipherMode.ccm(), Category.BLOCK, TlsCipherEngine.aes()),
//        AES_128_CCM_8(16, 0, 12, 4, null, TlsCipherMode.ccm8(), Category.BLOCK, TlsCipherEngine.aes()),
//        AES_128_GCM(16, 16, 12, 4, null, TlsCipherMode.gcm(), Category.BLOCK, TlsCipherEngine.aes()),
//        AES_256_CBC(32, 0, 16, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.aes()),
//        AES_256_CCM(32, 0, 12, 4, null, TlsCipherMode.ccm(), Category.BLOCK, TlsCipherEngine.aes()),
//        AES_256_CCM_8(32, 0, 12, 4, null, TlsCipherMode.ccm8(), Category.BLOCK, TlsCipherEngine.aes()),
//        AES_256_GCM(32, 16, 12, 4, null, TlsCipherMode.gcm(), Category.BLOCK, TlsCipherEngine.aes()),
//
//        ARIA_128_CBC(16, 0, 16, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.aria()),
//        ARIA_128_GCM(16, 16, 12, 4, null, TlsCipherMode.gcm(), Category.BLOCK, TlsCipherEngine.aria()),
//        ARIA_256_CBC(32, 0, 16, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.aria()),
//        ARIA_256_GCM(32, 16, 12, 4, null, TlsCipherMode.gcm(), Category.BLOCK, TlsCipherEngine.aria()),
//
//        CAMELLIA_128_CBC(16, 0, 16, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.camellia()),
//        CAMELLIA_128_GCM(16, 16, 12, 4, null, TlsCipherMode.gcm(), Category.BLOCK, TlsCipherEngine.camellia()),
//        CAMELLIA_256_CBC(32, 0, 16, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.camellia()),
//        CAMELLIA_256_GCM(32, 16, 12, 4, null, TlsCipherMode.gcm(), Category.BLOCK, TlsCipherEngine.camellia()),
//
//        CHACHA20_POLY1305(32, 0, 12, 12, null, TlsCipherMode.chacha20Poly1305(), Category.STREAM, TlsCipherEngine.chacha20()),
//
//        DES_40_CBC(5, 0, 8, 0, 7, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.des()),
//        DES_CBC(7, 0, 8, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.des()),
//        DES_CBC_40(5, 0, 8, 0, 7, TlsCipherMode.cbc40(), Category.BLOCK, TlsCipherEngine.des()),
//
//        IDEA_CBC(16, 0, 8, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.idea()),
//
//        KUZNYECHIK_CTR_OMAC(32, 0, 16, 4, null, TlsCipherMode.ctr(), Category.BLOCK, TlsCipherEngine.kuznyechik()),
//        KUZNYECHIK_MGM_L(32, 0, 12, 4, null, TlsCipherMode.mgmLight(), Category.BLOCK, TlsCipherEngine.kuznyechik()),
//        KUZNYECHIK_MGM_S(32, 0, 12, 4, null, TlsCipherMode.mgmStrong(), Category.BLOCK, TlsCipherEngine.kuznyechik()),
//
//        MAGMA_CTR(32, 0, 8, 4, null, TlsCipherMode.ctr(), Category.STREAM, TlsCipherEngine.magma()),
//        MAGMA_MGM_L(32, 0, 12, 4, null, TlsCipherMode.mgmLight(), Category.BLOCK, TlsCipherEngine.magma()),
//        MAGMA_MGM_S(32, 0, 12, 4, null, TlsCipherMode.mgmStrong(), Category.BLOCK, TlsCipherEngine.magma()),
//
//        RC2_CBC_40(5, 0, 8, 0, 16, TlsCipherMode.cbc40(), Category.BLOCK, TlsCipherEngine.rc2()),
//
//        RC4_128(16, 0, 0, 0, null, TlsCipherMode.ctr(), Category.STREAM, TlsCipherEngine.rc4()),
//        RC4_40(5, 0, 0, 0, 16, TlsCipherMode.ctr(), Category.STREAM, TlsCipherEngine.rc4()),
//
//        SEED_CBC(16, 0, 16, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.seed()),
//
//        SM4_CCM(16, 0, 12, 4, null, TlsCipherMode.ccm(), Category.BLOCK, TlsCipherEngine.sm4()),
//        SM4_GCM(16, 16, 12, 4, null, TlsCipherMode.gcm(), Category.BLOCK, TlsCipherEngine.sm4()),
//
//        DES_EDE_CBC(21, 0, 8, 0, null, TlsCipherMode.cbc(), Category.BLOCK, TlsCipherEngine.desEde());
//
//        private final int cipherKeyLength;
//        private final int tagLength;
//        private final int ivLength;
//        private final Integer expandedKeyLength;
//        private final int fixedIvLength;
//        private final TlsCipherMode mode;
//        private final Category category;
//        private final TlsCipherEngine engine;
//
//        Type(int cipherKeyLength, int tagLength, int ivLength, int fixedIvLength, Integer expandedKeyLength, TlsCipherMode mode, Category category, TlsCipherEngine engine) {
//            this.cipherKeyLength = cipherKeyLength;
//            this.tagLength = tagLength;
//            this.ivLength = ivLength;
//            this.expandedKeyLength = expandedKeyLength;
//            this.fixedIvLength = fixedIvLength;
//            this.mode = mode;
//            this.category = category;
//            this.engine = engine;
//        }
//
//        public int tagLength() {
//            return tagLength;
//        }
//
//        public int cipherKeyLength() {
//            return cipherKeyLength;
//        }
//
//        public int ivLength() {
//            return ivLength;
//        }
//
//        public OptionalInt expandedKeyLength() {
//            return expandedKeyLength == null ? OptionalInt.empty() : OptionalInt.of(expandedKeyLength);
//        }
//
//        public int fixedIvLength() {
//            return fixedIvLength;
//        }
//
//        public TlsCipherMode mode() {
//            return mode;
//        }
//
//        public TlsCipherEngine engine() {
//            return engine;
//        }
//
//        public Category category() {
//            return category;
//        }
//
//        public enum Category {
//            NULL,
//            STREAM,
//            BLOCK
//        }
//    }

public interface TlsCipherEngineType {
    static TlsCipherEngineType rc4() {
        return new RC4Engine();
    }

    static TlsCipherEngineType aes128() {
        return new AESEngine();
    }

    static TlsCipherEngineType aes256() {
        return new AESEngine();
    }

    static TlsCipherEngineType aria128() {
        return new ARIAEngine();
    }

    static TlsCipherEngineType aria256() {
        return new ARIAEngine();
    }

    static TlsCipherEngineType camellia128() {
        return new CamelliaEngine();
    }

    static TlsCipherEngineType camellia256() {
        return new CamelliaEngine();
    }

    static TlsCipherEngineType des() {
        return new DESEngine();
    }

    static TlsCipherEngineType des40() {
        return new DESEngine();
    }

    static TlsCipherEngineType idea() {
        return new IDEAEngine();
    }

    static TlsCipherEngineType kuznyechik() {
        return new KuznyechikEngine();
    }

    static TlsCipherEngineType magma() {
        return new MagmaEngine();
    }

    static TlsCipherEngineType rc2() {
        return new RC2Engine();
    }

    static TlsCipherEngineType seed() {
        return new SEEDEngine();
    }

    static TlsCipherEngineType sm4() {
        return new SM4Engine();
    }

    static TlsCipherEngineType desEde() {
        return new DESedeEngine();
    }

    static TlsCipherEngineType chacha20() {
        return null;
    }

    static TlsCipherEngineType none() {
        return null;
    }

    TlsCipherEngine newInstance(boolean forEncryption, byte[] key);
}
